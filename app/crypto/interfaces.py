"""Legacy interface sketch retained for compatibility with early-phase tests.

Concrete Phase 3/4 operations live in ``documents.service``, ``key_protection`` and
``encryption`` because those APIs carry the ownership and metadata needed for safe use.
"""


class CryptoService:
    """Provide a testable boundary for protected keys and document packages."""

    def protect_private_key(self, private_key: bytes, password: str) -> bytes:
        raise NotImplementedError("Use app.crypto.key_protection with an explicit key purpose")

    def hash_document(self, document: bytes) -> bytes:
        raise NotImplementedError("Use app.documents.service")

    def sign_detached(self, document: bytes, private_key: bytes) -> bytes:
        raise NotImplementedError("Use DocumentSigningService with an owned certificate")

    def verify_signature(self, document: bytes, package: bytes) -> None:
        raise NotImplementedError("Use DocumentSigningService.verify")

    def establish_x25519_key(self, peer_public_key: bytes, private_key: bytes) -> bytes:
        raise NotImplementedError("Use DocumentEncryptionService")

    def derive_key_hkdf(self, shared_secret: bytes, context: bytes) -> bytes:
        raise NotImplementedError("Use DocumentEncryptionService")

    def encrypt_aes_gcm(self, plaintext: bytes, key: bytes, aad: bytes) -> bytes:
        raise NotImplementedError("Use DocumentEncryptionService")

    def decrypt_aes_gcm(self, package: bytes, key: bytes, aad: bytes) -> bytes:
        raise NotImplementedError("Use DocumentEncryptionService")

    def parse_package(self, package: bytes) -> dict:
        raise NotImplementedError("Use app.documents.service")
