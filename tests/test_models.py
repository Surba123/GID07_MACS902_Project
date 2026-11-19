from datetime import timedelta

import pytest
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import (
    AuditEvent,
    Certificate,
    CertificateRequest,
    Document,
    EncryptedDocument,
    KeyRecord,
    RevocationRecord,
    SignatureRecord,
    User,
)
from app.models.common import utc_now


def make_user(name="Alice", email="Alice@Example.test"):
    user = User(full_name=name, email=email)
    user.set_password("example-password-for-tests")
    db.session.add(user)
    db.session.commit()
    return user


def test_all_phase_one_tables_exist(app):
    assert set(db.metadata.tables) == {
        "users",
        "key_records",
        "certificate_requests",
        "certificates",
        "revocation_records",
        "documents",
        "signature_records",
        "encrypted_documents",
        "audit_events",
    }


def test_email_normalization_and_uniqueness(app):
    make_user()
    second = User(full_name="Another", email=" alice@example.test ")
    second.set_password("another-test-password")
    db.session.add(second)
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()
    assert db.session.query(User).one().email == "alice@example.test"


def test_password_uses_argon2id_and_never_stores_plaintext(app):
    user = make_user()
    assert user.password_hash.startswith("$argon2id$")
    assert "example-password-for-tests" not in user.password_hash
    assert user.verify_password("example-password-for-tests")
    assert not user.verify_password("wrong-password")
    assert not hasattr(user, "password")


def test_relationships_and_unique_certificate_serial(app):
    user = make_user()
    reviewer = make_user("CA Admin", "admin@example.test")
    request = CertificateRequest(user=user, csr_data=b"placeholder-csr", reviewer=reviewer)
    db.session.add(request)
    db.session.flush()
    now = utc_now()
    cert = Certificate(
        user=user,
        request=request,
        serial_number="serial-one",
        subject="CN=Alice",
        issuer="CN=Issuing CA",
        certificate_data=b"placeholder-cert",
        fingerprint="fingerprint-one",
        valid_from=now,
        valid_until=now + timedelta(days=1),
    )
    db.session.add(cert)
    db.session.commit()
    assert user.certificate_requests[0] is request
    assert request.certificate is cert

    second_request = CertificateRequest(user=user, csr_data=b"another-csr")
    db.session.add(second_request)
    db.session.flush()
    db.session.add(
        Certificate(
            user=user,
            request=second_request,
            serial_number="serial-one",
            subject="CN=Alice",
            issuer="CN=Issuing CA",
            certificate_data=b"another-cert",
            fingerprint="fingerprint-two",
            valid_from=now,
            valid_until=now + timedelta(days=1),
        )
    )
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_document_metadata_and_foreign_keys(app):
    user = make_user()
    key = KeyRecord(user=user, purpose="signing", algorithm="RSA-PSS")
    document = Document(
        owner=user, original_filename="example.txt", storage_id="opaque-id", sha256_hash="a" * 64
    )
    encrypted = EncryptedDocument(
        sender=user,
        recipient=user,
        storage_id="encrypted-id",
        package_version="1",
        algorithm_metadata="{}",
    )
    event = AuditEvent(actor=user, action="test", target_type="document", outcome="success")
    db.session.add_all([key, document, encrypted, event])
    db.session.commit()
    assert document.owner is user
    assert key in user.keys
    assert encrypted.sender is user
    assert event.actor is user
    assert "password" not in (event.safe_detail or "")

    duplicate = Document(
        owner=user, original_filename="another.txt", storage_id="opaque-id", sha256_hash="b" * 64
    )
    db.session.add(duplicate)
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()

    orphan = Document(
        owner_id=999999,
        original_filename="orphan.txt",
        storage_id="orphan-id",
        sha256_hash="c" * 64,
    )
    db.session.add(orphan)
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_remaining_model_relationships_are_mapped():
    assert RevocationRecord.__table__.c.certificate_id.unique
    assert SignatureRecord.__table__.c.certificate_id.foreign_keys
