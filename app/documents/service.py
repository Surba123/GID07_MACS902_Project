"""Phase 3 detached document signing and verification.

Private keys enter this module only long enough to sign in the controlled local demo.
Packages contain public certificates only; the application timestamp is informational.
"""

import base64
import binascii
import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.crypto.key_protection import KeyProtectionError, unlock_private_key
from app.extensions import db
from app.models import AuditEvent, Certificate, Document, KeyRecord, SignatureRecord, User
from app.pki.service import PKIService

ALGORITHM = "RSA-PSS-SHA256"
HASH_ALGORITHM = "SHA-256"
PACKAGE_VERSION = "1"
ALLOWED_EXTENSIONS = {".pdf": "application/pdf", ".txt": "text/plain"}


class DocumentSigningError(ValueError):
    """A safe, user-presentable document signing or verification failure."""


@dataclass(frozen=True)
class VerificationResult:
    document_integrity_valid: bool
    signature_valid: bool
    certificate_currently_valid: bool
    chain_valid: bool
    revocation_checked: bool
    revoked: bool
    signing_authorized: bool
    signer_trusted: bool
    overall_valid: bool
    reasons: tuple[str, ...]
    signer_subject: str | None
    certificate_serial: str | None
    certificate_valid_from: datetime | None
    certificate_valid_until: datetime | None


def canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def validate_upload(filename: str | None, data: bytes, max_bytes: int) -> tuple[str, str]:
    if not filename or not data:
        raise DocumentSigningError("Select a non-empty PDF or plain-text document")
    if len(data) > max_bytes:
        raise DocumentSigningError("The document exceeds the configured upload size limit")
    # A client filename is metadata, not a path. Reject it rather than attempting to repair it.
    if Path(filename).name != filename or "\\" in filename or "/" in filename or "\x00" in filename:
        raise DocumentSigningError("Unsafe document filename")
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise DocumentSigningError("Only PDF and plain-text documents are accepted in this demo")
    return filename, ALLOWED_EXTENSIONS[suffix]


class DocumentSigningService:
    def __init__(
        self, *, upload_dir: Path, pki_service: PKIService, user_key_password: bytes, max_bytes: int
    ):
        self.upload_dir = Path(upload_dir).resolve()
        self.pki_service = pki_service
        self.user_key_password = user_key_password
        self.max_bytes = max_bytes

    @classmethod
    def from_config(cls, config: dict[str, object]) -> "DocumentSigningService":
        password = config.get("PKI_DEVELOPMENT_USER_KEY_PASSWORD")
        legacy_password = password.encode("utf-8") if isinstance(password, str) else b""
        return cls(
            upload_dir=Path(config["UPLOAD_DIR"]),
            pki_service=PKIService.from_config(config),
            user_key_password=legacy_password,
            max_bytes=int(config["MAX_CONTENT_LENGTH"]),
        )

    def sign_document(
        self,
        *,
        signer: User,
        certificate: Certificate,
        data: bytes,
        filename: str,
        password: str | None = None,
    ) -> SignatureRecord:
        safe_name, media_type = validate_upload(filename, data, self.max_bytes)
        if certificate.user_id != signer.id or certificate.status != "active":
            raise DocumentSigningError("The selected signer certificate is not active")
        crl_data = self._current_crl()
        trust = self.pki_service.validate_chain(
            certificate.certificate_data, at_time=datetime.now(UTC), crl_data=crl_data
        )
        if not trust.trusted:
            if "crl_not_current" in trust.reasons:
                raise DocumentSigningError(
                    "The certificate revocation list is out of date. "
                    "Ask a CA administrator to refresh the CRL before signing."
                )
            raise DocumentSigningError(
                "The signer certificate is not currently trusted: " + ", ".join(trust.reasons)
            )
        key_record = (
            db.session.query(KeyRecord)
            .filter_by(user_id=signer.id, purpose="signing", status="active")
            .one_or_none()
        )
        if key_record is None or not key_record.encrypted_private_key_data:
            raise DocumentSigningError(
                "No active protected signing key is available for this signer"
            )
        try:
            if key_record.private_key_kdf and key_record.private_key_kdf.startswith("scrypt-"):
                if password is None:
                    raise DocumentSigningError(
                        "Your current password is required to unlock the signing key"
                    )
                private_data = unlock_private_key(
                    key_record.encrypted_private_key_data,
                    password,
                    purpose="signing",
                    salt=key_record.private_key_salt,
                    nonce=key_record.private_key_nonce,
                )
                private_key = serialization.load_der_private_key(private_data, password=None)
            else:
                private_key = serialization.load_pem_private_key(
                    key_record.encrypted_private_key_data, self.user_key_password
                )
        except (TypeError, ValueError, KeyProtectionError) as error:
            raise DocumentSigningError("The protected signing key cannot be unlocked") from error
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise DocumentSigningError("The demo signing key is not RSA")
        public_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        certificate_public = (
            x509.load_pem_x509_certificate(certificate.certificate_data)
            .public_key()
            .public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        if public_bytes != certificate_public:
            raise DocumentSigningError(
                "The protected signing key does not match the selected certificate"
            )
        signing_time = datetime.now(UTC)
        digest = hashlib.sha256(data).hexdigest()
        manifest = {
            "certificate_fingerprint": certificate.fingerprint,
            "certificate_serial": certificate.serial_number,
            "document_sha256": digest,
            "hash_algorithm": HASH_ALGORITHM,
            "original_filename": safe_name,
            "signing_time": signing_time.isoformat(),
            "version": PACKAGE_VERSION,
        }
        manifest_bytes = canonical_json(manifest)
        signature = private_key.sign(
            manifest_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
            hashes.SHA256(),
        )
        storage_id = uuid.uuid4().hex
        self.upload_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        storage_path = self.upload_dir / storage_id
        storage_path.write_bytes(data)
        package = {
            "algorithm": ALGORITHM,
            "certificate_chain": {
                "issuing": _b64(self.pki_service.issuing_certificate_path.read_bytes()),
                "root": _b64(self.pki_service.root_certificate_path.read_bytes()),
                "signer": _b64(certificate.certificate_data),
            },
            "hash_algorithm": HASH_ALGORITHM,
            "manifest": manifest,
            "signature": _b64(signature),
            "version": PACKAGE_VERSION,
        }
        document = Document(
            owner=signer,
            original_filename=safe_name,
            media_type=media_type,
            byte_length=len(data),
            storage_id=storage_id,
            sha256_hash=digest,
        )
        record = SignatureRecord(
            public_id=str(uuid.uuid4()),
            document=document,
            signer=signer,
            certificate=certificate,
            manifest_data=manifest_bytes.decode("utf-8"),
            signature_data=signature,
            package_data=canonical_json(package),
            algorithm=ALGORITHM,
            package_version=PACKAGE_VERSION,
            signing_time=signing_time,
        )
        db.session.add_all(
            [
                document,
                record,
                AuditEvent(
                    actor=signer,
                    action="document_signed",
                    target_type="signature",
                    target_id=record.public_id,
                    outcome="success",
                    safe_detail=f"sha256={digest}",
                ),
            ]
        )
        db.session.flush()
        return record

    def verify(self, *, data: bytes, package_data: bytes) -> VerificationResult:
        try:
            package = _parse_package(package_data)
            manifest = package["manifest"]
            signer_pem = _unb64(package["certificate_chain"]["signer"])
            issuing_pem = _unb64(package["certificate_chain"]["issuing"])
            root_pem = _unb64(package["certificate_chain"]["root"])
            signature = _unb64(package["signature"])
            cert = x509.load_pem_x509_certificate(signer_pem)
            if manifest["certificate_fingerprint"] != cert.fingerprint(
                hashes.SHA256()
            ).hex() or manifest["certificate_serial"] != str(cert.serial_number):
                raise DocumentSigningError("Certificate does not match signature manifest")
        except (DocumentSigningError, ValueError, KeyError, TypeError):
            return _failed_result("malformed_signature_package")
        digest_matches = hashlib.sha256(data).hexdigest() == manifest["document_sha256"]
        signature_valid = True
        try:
            cert.public_key().verify(
                signature,
                canonical_json(manifest),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size
                ),
                hashes.SHA256(),
            )
        except (InvalidSignature, TypeError, ValueError):
            signature_valid = False
        trust = self.pki_service.validate_chain(
            signer_pem,
            at_time=datetime.now(UTC),
            crl_data=self._current_crl(),
            issuing_certificate=issuing_pem,
            root_certificate=root_pem,
        )
        reasons = list(trust.reasons)
        if not digest_matches:
            reasons.append("document_digest_mismatch")
        if not signature_valid:
            reasons.append("invalid_document_signature")
        overall = digest_matches and signature_valid and trust.trusted
        return VerificationResult(
            digest_matches,
            signature_valid,
            trust.currently_valid,
            trust.chain_valid,
            trust.revocation_checked,
            trust.revoked,
            trust.usage_valid,
            trust.trusted,
            overall,
            tuple(reasons),
            cert.subject.rfc4514_string(),
            str(cert.serial_number),
            cert.not_valid_before_utc,
            cert.not_valid_after_utc,
        )

    def _current_crl(self) -> bytes | None:
        return (
            self.pki_service.crl_path.read_bytes() if self.pki_service.crl_path.is_file() else None
        )


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: object) -> bytes:
    if not isinstance(value, str):
        raise DocumentSigningError("Invalid base64 field")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise DocumentSigningError("Invalid base64 field") from error


def _parse_package(data: bytes) -> dict[str, Any]:
    try:
        package = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DocumentSigningError("Malformed signature package") from error
    if not isinstance(package, dict) or set(package) != {
        "algorithm",
        "certificate_chain",
        "hash_algorithm",
        "manifest",
        "signature",
        "version",
    }:
        raise DocumentSigningError("Unsupported signature package fields")
    if (
        package["version"] != PACKAGE_VERSION
        or package["algorithm"] != ALGORITHM
        or package["hash_algorithm"] != HASH_ALGORITHM
    ):
        raise DocumentSigningError("Unsupported signature package algorithm or version")
    manifest = package["manifest"]
    expected_manifest = {
        "certificate_fingerprint",
        "certificate_serial",
        "document_sha256",
        "hash_algorithm",
        "original_filename",
        "signing_time",
        "version",
    }
    if (
        not isinstance(manifest, dict)
        or set(manifest) != expected_manifest
        or manifest["version"] != PACKAGE_VERSION
        or manifest["hash_algorithm"] != HASH_ALGORITHM
    ):
        raise DocumentSigningError("Malformed signature manifest")
    if not isinstance(manifest["document_sha256"], str) or len(manifest["document_sha256"]) != 64:
        raise DocumentSigningError("Malformed document digest")
    if not isinstance(package["certificate_chain"], dict) or set(package["certificate_chain"]) != {
        "signer",
        "issuing",
        "root",
    }:
        raise DocumentSigningError("Malformed certificate chain")
    return package


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DocumentSigningError("Duplicate JSON package field")
        result[key] = value
    return result


def _failed_result(reason: str) -> VerificationResult:
    return VerificationResult(
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        (reason,),
        None,
        None,
        None,
        None,
    )
