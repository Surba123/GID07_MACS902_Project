import pytest

from app.crypto.interfaces import CryptoService


@pytest.mark.parametrize(
    "method,args",
    [
        ("protect_private_key", (b"private", "password")),
        ("hash_document", (b"document",)),
        ("sign_detached", (b"document", b"key")),
        ("verify_signature", (b"document", b"package")),
        ("parse_package", (b"package",)),
        ("establish_x25519_key", (b"public", b"private")),
        ("derive_key_hkdf", (b"secret", b"context")),
        ("encrypt_aes_gcm", (b"plain", b"key", b"aad")),
        ("decrypt_aes_gcm", (b"package", b"key", b"aad")),
    ],
)
def test_crypto_stubs_fail_explicitly(method, args):
    with pytest.raises(NotImplementedError):
        getattr(CryptoService(), method)(*args)
