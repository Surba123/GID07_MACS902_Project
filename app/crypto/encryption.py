"""Recipient-targeted X25519, HKDF-SHA256 and AES-256-GCM document encryption."""

import base64
import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.crypto.key_protection import KeyProtectionError, unlock_private_key
from app.extensions import db
from app.models import AuditEvent, EncryptedDocument, KeyRecord, User

VERSION = "1"
ALGORITHMS = "X25519-HKDF-SHA256-AES-256-GCM"
INFO = b"MACS902 document encryption v1"


class DocumentEncryptionError(ValueError):
    """A safe encryption/decryption workflow failure."""


@dataclass(frozen=True)
class DecryptedDocument:
    data: bytes
    filename: str
    media_type: str


class DocumentEncryptionService:
    def __init__(self, encrypted_dir: Path, max_bytes: int):
        self.encrypted_dir = Path(encrypted_dir).resolve()
        self.max_bytes = max_bytes

    @classmethod
    def from_config(cls, config):
        return cls(Path(config["ENCRYPTED_DIR"]), int(config["MAX_CONTENT_LENGTH"]))

    def encrypt(
        self, *, sender: User, recipient: User, data: bytes, filename: str
    ) -> EncryptedDocument:
        safe_name, media_type = _validate_upload(filename, data, self.max_bytes)
        recipient_key = _active_key(recipient.id, "key_agreement")
        try:
            recipient_public = x25519.X25519PublicKey.from_public_bytes(
                recipient_key.public_key_data
            )
        except (TypeError, ValueError) as error:
            raise DocumentEncryptionError("The recipient encryption key is invalid") from error
        ephemeral = x25519.X25519PrivateKey.generate()
        ephemeral_public = ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        salt = os.urandom(16)
        nonce = os.urandom(12)
        public_id = str(uuid.uuid4())
        metadata = {
            "algorithms": ALGORITHMS,
            "ephemeral_public_key": _b64(ephemeral_public),
            "filename": safe_name,
            "media_type": media_type,
            "public_id": public_id,
            "recipient_id": recipient.id,
            "salt": _b64(salt),
            "sender_id": sender.id,
            "version": VERSION,
        }
        content_key = _content_key(ephemeral.exchange(recipient_public), salt, metadata)
        ciphertext = AESGCM(content_key).encrypt(nonce, data, canonical_json(metadata))
        storage_id = uuid.uuid4().hex
        self.encrypted_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        (self.encrypted_dir / storage_id).write_bytes(ciphertext)
        record = EncryptedDocument(
            public_id=public_id,
            sender=sender,
            recipient=recipient,
            original_filename=safe_name,
            media_type=media_type,
            byte_length=len(data),
            storage_id=storage_id,
            package_version=VERSION,
            algorithm_metadata=json.dumps(
                {**metadata, "nonce": _b64(nonce)}, sort_keys=True, separators=(",", ":")
            ),
        )
        db.session.add_all(
            [
                record,
                AuditEvent(
                    actor=sender,
                    action="document_encrypted",
                    target_type="encrypted_document",
                    target_id=public_id,
                    outcome="success",
                    safe_detail=f"recipient_id={recipient.id}",
                ),
            ]
        )
        db.session.flush()
        return record

    def decrypt(
        self, *, record: EncryptedDocument, recipient: User, password: str
    ) -> DecryptedDocument:
        if record.recipient_id != recipient.id:
            raise DocumentEncryptionError("Only the intended recipient may decrypt this document")
        try:
            metadata_with_nonce = json.loads(record.algorithm_metadata)
            nonce = _unb64(metadata_with_nonce.pop("nonce"))
            metadata = metadata_with_nonce
            if (
                metadata["public_id"] != record.public_id
                or metadata["recipient_id"] != recipient.id
                or metadata["version"] != VERSION
                or metadata["algorithms"] != ALGORITHMS
            ):
                raise ValueError
            salt = _unb64(metadata["salt"])
            ephemeral_public = x25519.X25519PublicKey.from_public_bytes(
                _unb64(metadata["ephemeral_public_key"])
            )
            key_record = _active_key(recipient.id, "key_agreement")
            raw_private = unlock_private_key(
                key_record.encrypted_private_key_data,
                password,
                purpose="key_agreement",
                salt=key_record.private_key_salt,
                nonce=key_record.private_key_nonce,
            )
            private_key = x25519.X25519PrivateKey.from_private_bytes(raw_private)
            ciphertext = (self.encrypted_dir / record.storage_id).read_bytes()
            plaintext = AESGCM(
                _content_key(private_key.exchange(ephemeral_public), salt, metadata)
            ).decrypt(nonce, ciphertext, canonical_json(metadata))
        except (KeyError, TypeError, ValueError, OSError, InvalidTag, KeyProtectionError) as error:
            raise DocumentEncryptionError(
                "Decryption failed: wrong password, wrong recipient, or altered encrypted data"
            ) from error
        db.session.add(
            AuditEvent(
                actor=recipient,
                action="document_decrypted",
                target_type="encrypted_document",
                target_id=record.public_id,
                outcome="success",
            )
        )
        return DecryptedDocument(plaintext, record.original_filename, record.media_type)


def _active_key(user_id: int, purpose: str) -> KeyRecord:
    key = (
        db.session.query(KeyRecord)
        .filter_by(user_id=user_id, purpose=purpose, status="active")
        .one_or_none()
    )
    if key is None or not key.public_key_data or not key.encrypted_private_key_data:
        raise DocumentEncryptionError("The required recipient encryption key is unavailable")
    return key


def _content_key(shared_secret: bytes, salt: bytes, metadata: dict[str, Any]) -> bytes:
    binding = hashlib.sha256(canonical_json(metadata)).digest()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=INFO + binding).derive(
        shared_secret
    )


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _validate_upload(filename: str, data: bytes, max_bytes: int) -> tuple[str, str]:
    if not filename or not data:
        raise DocumentEncryptionError("Select a non-empty PDF or plain-text document")
    if len(data) > max_bytes:
        raise DocumentEncryptionError("The document exceeds the configured upload size limit")
    if Path(filename).name != filename or "\\" in filename or "/" in filename or "\x00" in filename:
        raise DocumentEncryptionError("Unsafe document filename")
    media_types = {".pdf": "application/pdf", ".txt": "text/plain"}
    try:
        return filename, media_types[Path(filename).suffix.lower()]
    except KeyError as error:
        raise DocumentEncryptionError("Only PDF and plain-text documents are accepted") from error
