"""Password-derived authenticated encryption for per-user private keys."""

import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SALT_BYTES = 16
NONCE_BYTES = 12


class KeyProtectionError(ValueError):
    """The key envelope could not be created or unlocked."""


@dataclass(frozen=True)
class ProtectedKey:
    ciphertext: bytes
    salt: bytes
    nonce: bytes
    kdf: str = "scrypt-n16384-r8-p1-aes256gcm-v1"


def protect_private_key(private_key: bytes, password: str, *, purpose: str) -> ProtectedKey:
    if len(password) < 12:
        raise KeyProtectionError("The password must contain at least 12 characters")
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    key = _derive(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, private_key, _aad(purpose))
    return ProtectedKey(ciphertext=ciphertext, salt=salt, nonce=nonce)


def unlock_private_key(
    ciphertext: bytes, password: str, *, purpose: str, salt: bytes, nonce: bytes
) -> bytes:
    if len(salt) != SALT_BYTES or len(nonce) != NONCE_BYTES:
        raise KeyProtectionError("The protected private-key metadata is invalid")
    try:
        return AESGCM(_derive(password, salt)).decrypt(nonce, ciphertext, _aad(purpose))
    except (InvalidTag, ValueError) as error:
        raise KeyProtectionError(
            "The password is incorrect or the protected key was altered"
        ) from error


def _derive(password: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(
        password.encode("utf-8")
    )


def _aad(purpose: str) -> bytes:
    if purpose not in {"signing", "key_agreement"}:
        raise KeyProtectionError("Unsupported private-key purpose")
    return f"MACS902:user-private-key:{purpose}:v1".encode()
