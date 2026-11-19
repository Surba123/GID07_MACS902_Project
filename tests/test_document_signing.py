import json
from datetime import UTC, datetime, timedelta
from io import BytesIO

import pytest

from app.documents.service import DocumentSigningError, DocumentSigningService, _b64
from app.extensions import db
from app.models import KeyRecord, SignatureRecord, User
from app.pki.lifecycle import (
    persist_issued_certificate,
    revocation_entries,
    revoke_persisted_certificate,
)
from app.pki.service import PKIService


@pytest.fixture
def signing_material(app):
    now = datetime.now(UTC)
    service = PKIService(
        ca_key_dir=app.config["CA_KEY_DIR"],
        ca_cert_dir=app.config["CA_CERT_DIR"],
        ca_key_password=app.config["PKI_CA_KEY_PASSWORD"].encode(),
    )
    service.initialize_hierarchy(now=now)
    service.write_crl(
        service.generate_crl([], this_update=now, next_update=now + timedelta(days=2))
    )
    signer = User(full_name="Alice Example", email="alice@example.test", status="disabled")
    signer.set_password("not-a-private-key")
    db.session.add(signer)
    db.session.flush()
    generated = service.generate_user_csr(
        common_name="Alice Example",
        email="alice@example.test",
        private_key_password=app.config["PKI_DEVELOPMENT_USER_KEY_PASSWORD"].encode(),
    )
    certificate = persist_issued_certificate(
        user=signer,
        reviewer=None,
        csr_pem=generated.csr_pem,
        certificate_pem=service.issue_certificate(
            generated.csr_pem, valid_until=now + timedelta(days=30), now=now
        ),
        reviewed_at=now,
    )
    db.session.add(
        KeyRecord(
            user=signer,
            purpose="signing",
            algorithm="RSA-3072",
            public_key_data=generated.public_key_pem,
            public_key_fingerprint=generated.public_key_fingerprint,
            encrypted_private_key_data=generated.encrypted_private_key_pem,
            private_key_kdf="PKCS8-BestAvailableEncryption",
            status="active",
        )
    )
    db.session.commit()
    return DocumentSigningService.from_config(app.config), service, signer, certificate


def test_sign_and_verify_exact_document_bytes(signing_material):
    document_service, _, signer, certificate = signing_material
    record = document_service.sign_document(
        signer=signer,
        certificate=certificate,
        data=b"important exact bytes\n",
        filename="report.txt",
    )
    db.session.commit()
    result = document_service.verify(
        data=b"important exact bytes\n", package_data=record.package_data
    )
    assert result.overall_valid
    assert result.document_integrity_valid and result.signature_valid and result.signer_trusted
    assert (
        db.session.query(SignatureRecord).one().signature_data
        not in db.session.query(KeyRecord).one().encrypted_private_key_data
    )


def test_tampered_document_and_corrupt_signature_fail(signing_material):
    document_service, _, signer, certificate = signing_material
    record = document_service.sign_document(
        signer=signer, certificate=certificate, data=b"original", filename="report.txt"
    )
    db.session.commit()
    changed = document_service.verify(data=b"changed", package_data=record.package_data)
    assert not changed.document_integrity_valid
    assert changed.signature_valid
    package = json.loads(record.package_data)
    package["signature"] = _b64(b"corrupt")
    corrupted = document_service.verify(data=b"original", package_data=json.dumps(package).encode())
    assert not corrupted.signature_valid


def test_revoked_certificate_keeps_math_but_loses_trust(signing_material):
    document_service, pki, signer, certificate = signing_material
    record = document_service.sign_document(
        signer=signer, certificate=certificate, data=b"original", filename="report.txt"
    )
    administrator = User(
        full_name="CA Admin", email="ca-admin@example.test", role="ca_admin", status="disabled"
    )
    administrator.set_password("not-a-private-key")
    db.session.add(administrator)
    db.session.flush()
    revoke_persisted_certificate(
        certificate=certificate, administrator=administrator, reason="key_compromise"
    )
    db.session.commit()
    now = datetime.now(UTC)
    pki.write_crl(
        pki.generate_crl(revocation_entries(), this_update=now, next_update=now + timedelta(days=2))
    )
    result = document_service.verify(data=b"original", package_data=record.package_data)
    assert result.signature_valid and result.document_integrity_valid
    assert result.revoked and not result.signer_trusted and not result.overall_valid


@pytest.mark.parametrize("filename", ["../secret.txt", "..\\secret.txt", "report.exe"])
def test_unsafe_or_unsupported_filename_is_rejected(signing_material, filename):
    document_service, _, signer, certificate = signing_material
    with pytest.raises(DocumentSigningError):
        document_service.sign_document(
            signer=signer, certificate=certificate, data=b"x", filename=filename
        )


def test_oversized_and_malformed_package_fail_safely(signing_material):
    document_service, _, signer, certificate = signing_material
    with pytest.raises(DocumentSigningError, match="exceeds"):
        document_service.sign_document(
            signer=signer,
            certificate=certificate,
            data=b"x" * (document_service.max_bytes + 1),
            filename="report.txt",
        )
    result = document_service.verify(data=b"x", package_data=b"not json")
    assert not result.overall_valid
    assert result.reasons == ("malformed_signature_package",)


def test_demo_routes_are_available_and_reject_unknown_signature(client):
    assert client.get("/documents/").status_code == 200
    response = client.post(
        "/documents/verify",
        data={"document": (BytesIO(b"document"), "report.txt"), "signature_id": "999"},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Select a stored signature record" in response.data
