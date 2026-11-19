import json
import secrets
from datetime import UTC, datetime, timedelta
from io import BytesIO

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from app.crypto.encryption import DocumentEncryptionError, DocumentEncryptionService
from app.crypto.key_protection import KeyProtectionError, protect_private_key, unlock_private_key
from app.documents.service import DocumentSigningError, DocumentSigningService
from app.extensions import db
from app.models import (
    Certificate,
    CertificateRequest,
    EncryptedDocument,
    KeyRecord,
    SignatureRecord,
    User,
)
from app.pki.service import PKIService
from app.pki.workflow import approve_request, create_signing_request

PASSWORD = secrets.token_urlsafe(24)


def _user(name: str, email: str) -> User:
    user = User(full_name=name, email=email)
    user.set_password(PASSWORD)
    private_key = x25519.X25519PrivateKey.generate()
    raw = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    protected = protect_private_key(raw, PASSWORD, purpose="key_agreement")
    db.session.add_all(
        [
            user,
            KeyRecord(
                user=user,
                purpose="key_agreement",
                algorithm="X25519",
                public_key_data=private_key.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                ),
                encrypted_private_key_data=protected.ciphertext,
                private_key_kdf=protected.kdf,
                private_key_salt=protected.salt,
                private_key_nonce=protected.nonce,
                status="active",
            ),
        ]
    )
    db.session.commit()
    return user


def _pki(app) -> PKIService:
    app.config["PKI_CA_KEY_PASSWORD"] = secrets.token_urlsafe(32)
    service = PKIService.from_config(app.config)
    now = datetime.now(UTC)
    service.initialize_hierarchy(now=now)
    service.write_crl(
        service.generate_crl([], this_update=now, next_update=now + timedelta(days=2))
    )
    return service


def test_password_key_envelope_uses_scrypt_and_aes_gcm():
    plaintext = b"private-key-material"
    protected = protect_private_key(plaintext, PASSWORD, purpose="signing")
    assert plaintext not in protected.ciphertext
    assert protected.kdf == "scrypt-n16384-r8-p1-aes256gcm-v1"
    assert len(protected.salt) == 16 and len(protected.nonce) == 12
    assert (
        unlock_private_key(
            protected.ciphertext,
            PASSWORD,
            purpose="signing",
            salt=protected.salt,
            nonce=protected.nonce,
        )
        == plaintext
    )
    with pytest.raises(KeyProtectionError):
        unlock_private_key(
            protected.ciphertext,
            PASSWORD + "-incorrect",
            purpose="signing",
            salt=protected.salt,
            nonce=protected.nonce,
        )


def test_registration_login_logout_and_generic_failure(client, app):
    response = client.post(
        "/auth/register",
        data={
            "full_name": "Alice Example",
            "email": "alice@example.com",
            "password": PASSWORD,
            "confirm_password": PASSWORD,
        },
        follow_redirects=True,
    )
    assert response.status_code == 200 and b"My dashboard" in response.data
    user = db.session.query(User).one()
    key = db.session.query(KeyRecord).filter_by(purpose="key_agreement").one()
    assert user.password_hash.startswith("$argon2id$")
    assert PASSWORD.encode() not in key.encrypted_private_key_data
    client.post("/auth/logout")
    unknown = client.post(
        "/auth/login", data={"email": "missing@example.com", "password": "wrong-password"}
    )
    wrong = client.post("/auth/login", data={"email": user.email, "password": "wrong-password"})
    assert b"Invalid email or password" in unknown.data
    assert b"Invalid email or password" in wrong.data
    assert client.get("/auth/dashboard").status_code == 302


def test_csrf_and_admin_authorization(client, app):
    user = _user("Alice", "alice@example.com")
    client.post("/auth/login", data={"email": user.email, "password": PASSWORD})
    assert client.get("/admin/").status_code == 403
    app.config["WTF_CSRF_ENABLED"] = True
    assert client.post("/auth/logout").status_code == 400


def test_admin_bootstrap_cli_never_prints_password(app):
    result = app.test_cli_runner().invoke(
        args=[
            "users",
            "bootstrap-admin",
            "--name",
            "Local Admin",
            "--email",
            "admin@example.com",
        ],
        input=f"{PASSWORD}\n{PASSWORD}\n",
    )
    assert result.exit_code == 0
    assert PASSWORD not in result.output
    assert db.session.query(User).filter_by(role="ca_admin").one().verify_password(PASSWORD)


def test_certificate_approval_and_authenticated_signing(app):
    pki = _pki(app)
    alice = _user("Alice", "alice@example.com")
    admin = User(full_name="Admin", email="admin@example.com", role="ca_admin")
    admin.set_password(PASSWORD)
    db.session.add(admin)
    db.session.commit()
    request = create_signing_request(user=alice, password=PASSWORD, pki=pki)
    db.session.commit()
    certificate = approve_request(request=request, administrator=admin, pki=pki)
    db.session.commit()
    key = db.session.query(KeyRecord).filter_by(user_id=alice.id, purpose="signing").one()
    assert key.private_key_kdf.startswith("scrypt-")
    assert b"PRIVATE KEY" not in key.encrypted_private_key_data
    service = DocumentSigningService.from_config(app.config)
    record = service.sign_document(
        signer=alice,
        certificate=certificate,
        data=b"owned document",
        filename="owned.txt",
        password=PASSWORD,
    )
    db.session.commit()
    assert service.verify(data=b"owned document", package_data=record.package_data).overall_valid
    bob = _user("Bob", "bob@example.com")
    with pytest.raises(DocumentSigningError, match="not active"):
        service.sign_document(
            signer=bob,
            certificate=certificate,
            data=b"stolen",
            filename="stolen.txt",
            password=PASSWORD,
        )


def test_recipient_encryption_decryption_access_and_tamper(app):
    alice = _user("Alice", "alice@example.com")
    bob = _user("Bob", "bob@example.com")
    mallory = _user("Mallory", "mallory@example.com")
    service = DocumentEncryptionService.from_config(app.config)
    first = service.encrypt(
        sender=alice, recipient=bob, data=b"secret exact bytes", filename="secret.txt"
    )
    second = service.encrypt(
        sender=alice, recipient=bob, data=b"secret exact bytes", filename="secret.txt"
    )
    db.session.commit()
    first_metadata = json.loads(first.algorithm_metadata)
    second_metadata = json.loads(second.algorithm_metadata)
    assert first_metadata["salt"] != second_metadata["salt"]
    assert first_metadata["nonce"] != second_metadata["nonce"]
    assert first_metadata["ephemeral_public_key"] != second_metadata["ephemeral_public_key"]
    assert (
        service.decrypt(record=first, recipient=bob, password=PASSWORD).data
        == b"secret exact bytes"
    )
    with pytest.raises(DocumentEncryptionError, match="altered"):
        service.decrypt(record=first, recipient=bob, password=PASSWORD + "-incorrect")
    with pytest.raises(DocumentEncryptionError, match="intended recipient"):
        service.decrypt(record=first, recipient=mallory, password=PASSWORD)
    original_metadata = first.algorithm_metadata
    changed_metadata = json.loads(original_metadata)
    changed_metadata["filename"] = "substituted.txt"
    first.algorithm_metadata = json.dumps(changed_metadata)
    with pytest.raises(DocumentEncryptionError, match="altered"):
        service.decrypt(record=first, recipient=bob, password=PASSWORD)
    first.algorithm_metadata = original_metadata
    path = service.encrypted_dir / first.storage_id
    altered = bytearray(path.read_bytes())
    altered[-1] ^= 1
    path.write_bytes(altered)
    with pytest.raises(DocumentEncryptionError, match="altered"):
        service.decrypt(record=first, recipient=bob, password=PASSWORD)


def test_cross_user_decrypt_route_is_forbidden(client, app):
    alice = _user("Alice", "alice@example.com")
    bob = _user("Bob", "bob@example.com")
    record = DocumentEncryptionService.from_config(app.config).encrypt(
        sender=alice, recipient=bob, data=b"private", filename="private.txt"
    )
    db.session.commit()
    client.post("/auth/login", data={"email": alice.email, "password": PASSWORD})
    response = client.post(
        f"/documents/encrypted/{record.public_id}/decrypt", data={"password": PASSWORD}
    )
    assert response.status_code == 403


def test_authenticated_encrypt_route(client, app):
    alice = _user("Alice", "alice@example.com")
    bob = _user("Bob", "bob@example.com")
    client.post("/auth/login", data={"email": alice.email, "password": PASSWORD})
    response = client.post(
        "/documents/encrypt",
        data={
            "recipient_id": str(bob.id),
            "document": (BytesIO(b"confidential"), "confidential.txt"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert db.session.query(EncryptedDocument).one().recipient_id == bob.id


def test_encrypt_route_rejects_disabled_recipient(client, app):
    alice = _user("Alice", "alice@example.com")
    bob = _user("Bob", "bob@example.com")
    bob.status = "disabled"
    db.session.commit()
    client.post("/auth/login", data={"email": alice.email, "password": PASSWORD})

    response = client.post(
        "/documents/encrypt",
        data={
            "recipient_id": str(bob.id),
            "document": (BytesIO(b"confidential"), "confidential.txt"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"another active recipient" in response.data
    assert db.session.query(EncryptedDocument).count() == 0


def test_admin_routes_issue_and_revoke_certificate(client, app):
    pki = _pki(app)
    alice = _user("Alice", "alice@example.com")
    administrator = User(full_name="Administrator", email="admin@example.com", role="ca_admin")
    administrator.set_password(PASSWORD)
    db.session.add(administrator)
    db.session.commit()
    certificate_request = create_signing_request(user=alice, password=PASSWORD, pki=pki)
    db.session.commit()
    stale_time = datetime.now(UTC) - timedelta(days=8)
    pki.write_crl(
        pki.generate_crl([], this_update=stale_time, next_update=stale_time + timedelta(days=7))
    )
    client.post("/auth/login", data={"email": administrator.email, "password": PASSWORD})
    assert client.get("/admin/").status_code == 200
    issue = client.post(f"/admin/requests/{certificate_request.id}/approve", follow_redirects=True)
    assert issue.status_code == 200
    assert b"Certificate issued and CRL refreshed" in issue.data
    issued = db.session.query(Certificate).one()
    assert issued.status == "active"
    assert pki.validate_chain(
        issued.certificate_data,
        at_time=datetime.now(UTC),
        crl_data=pki.crl_path.read_bytes(),
    ).trusted
    refreshed = client.post("/admin/crl/refresh", follow_redirects=True)
    assert refreshed.status_code == 200
    assert b"Certificate revocation list refreshed" in refreshed.data
    revoked = client.post(
        f"/admin/certificates/{issued.id}/revoke",
        data={"reason": "key_compromise"},
        follow_redirects=True,
    )
    assert revoked.status_code == 200
    assert issued.status == "revoked"


def test_signature_package_download_is_owner_only(client, app):
    pki = _pki(app)
    alice = _user("Alice", "alice@example.com")
    administrator = User(full_name="Administrator", email="admin@example.com", role="ca_admin")
    administrator.set_password(PASSWORD)
    db.session.add(administrator)
    db.session.commit()
    certificate_request = create_signing_request(user=alice, password=PASSWORD, pki=pki)
    db.session.commit()
    certificate = approve_request(request=certificate_request, administrator=administrator, pki=pki)
    db.session.commit()
    service = DocumentSigningService.from_config(app.config)
    record = service.sign_document(
        signer=alice,
        certificate=certificate,
        data=b"portable signature document",
        filename="portable.txt",
        password=PASSWORD,
    )
    db.session.commit()
    client.post("/auth/login", data={"email": alice.email, "password": PASSWORD})
    download = client.get(f"/documents/signatures/{record.public_id}/package")
    assert download.status_code == 200
    assert download.data == record.package_data
    client.post("/auth/logout")
    other = _user("Other", "other@example.com")
    client.post("/auth/login", data={"email": other.email, "password": PASSWORD})
    assert client.get(f"/documents/signatures/{record.public_id}/package").status_code == 403


def test_complete_fresh_runtime_demo_flow(client, app):
    _pki(app)
    runner = app.test_cli_runner()
    bootstrap = runner.invoke(
        args=[
            "users",
            "bootstrap-admin",
            "--name",
            "Demo Administrator",
            "--email",
            "admin@example.com",
        ],
        input=f"{PASSWORD}\n{PASSWORD}\n",
    )
    assert bootstrap.exit_code == 0

    for name, email in (("Alice Example", "alice@example.com"), ("Bob Example", "bob@example.com")):
        registered = client.post(
            "/auth/register",
            data={
                "full_name": name,
                "email": email,
                "password": PASSWORD,
                "confirm_password": PASSWORD,
            },
            follow_redirects=True,
        )
        assert registered.status_code == 200 and b"My dashboard" in registered.data
        requested = client.post(
            "/auth/request-signing-certificate",
            data={"password": PASSWORD},
            follow_redirects=True,
        )
        assert b"submitted for administrator review" in requested.data
        client.post("/auth/logout")

    client.post("/auth/login", data={"email": "admin@example.com", "password": PASSWORD})
    for request_record in db.session.query(CertificateRequest).filter_by(status="pending").all():
        issued = client.post(f"/admin/requests/{request_record.id}/approve", follow_redirects=True)
        assert b"Certificate issued" in issued.data
    client.post("/auth/logout")

    alice = db.session.query(User).filter_by(email="alice@example.com").one()
    bob = db.session.query(User).filter_by(email="bob@example.com").one()
    client.post("/auth/login", data={"email": alice.email, "password": PASSWORD})
    signed = client.post(
        "/documents/sign",
        data={
            "password": PASSWORD,
            "document": (BytesIO(b"release demo document"), "demo.txt"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert b"Document signed" in signed.data
    signature = db.session.query(SignatureRecord).one()

    verified = client.post(
        "/documents/verify",
        data={
            "signature_id": str(signature.id),
            "document": (BytesIO(b"release demo document"), "demo.txt"),
        },
        content_type="multipart/form-data",
    )
    assert b"Signature and signer are valid" in verified.data
    tampered = client.post(
        "/documents/verify",
        data={
            "signature_id": str(signature.id),
            "document": (BytesIO(b"tampered demo document"), "demo.txt"),
        },
        content_type="multipart/form-data",
    )
    assert b"uploaded bytes do not match" in tampered.data

    encrypted = client.post(
        "/documents/encrypt",
        data={
            "recipient_id": str(bob.id),
            "document": (BytesIO(b"recipient-only content"), "private.txt"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert b"encrypted for the selected recipient" in encrypted.data
    encrypted_record = db.session.query(EncryptedDocument).one()
    denied = client.post(
        f"/documents/encrypted/{encrypted_record.public_id}/decrypt",
        data={"password": PASSWORD},
    )
    assert denied.status_code == 403
    client.post("/auth/logout")

    client.post("/auth/login", data={"email": bob.email, "password": PASSWORD})
    decrypted = client.post(
        f"/documents/encrypted/{encrypted_record.public_id}/decrypt",
        data={"password": PASSWORD},
    )
    assert decrypted.status_code == 200 and decrypted.data == b"recipient-only content"
    client.post("/auth/logout")

    client.post("/auth/login", data={"email": "admin@example.com", "password": PASSWORD})
    alice_certificate = db.session.query(Certificate).filter_by(user_id=alice.id).one()
    revoked = client.post(
        f"/admin/certificates/{alice_certificate.id}/revoke",
        data={"reason": "key_compromise"},
        follow_redirects=True,
    )
    assert b"Certificate revoked and CRL refreshed" in revoked.data
    client.post("/auth/logout")

    revoked_result = client.post(
        "/documents/verify",
        data={
            "document": (BytesIO(b"release demo document"), "demo.txt"),
            "package": (BytesIO(signature.package_data), "signature.json"),
        },
        content_type="multipart/form-data",
    )
    assert b"RSA-PSS signature is mathematically valid" in revoked_result.data
    assert b"signer certificate has been revoked" in revoked_result.data
