from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.extensions import db
from app.models import Certificate, RevocationRecord, User
from app.pki.errors import CertificateIssuanceError, CSRValidationError, RevocationError
from app.pki.lifecycle import (
    persist_issued_certificate,
    revocation_entries,
    revoke_persisted_certificate,
)
from app.pki.service import DOCUMENT_SIGNING_EKU, PKIService
from app.pki.types import RevocationEntry

NOW = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)
CA_PASSWORD = b"test-ca-password-with-adequate-length"
USER_PASSWORD = b"test-user-password-with-adequate-length"


@pytest.fixture(scope="module")
def pki_service(tmp_path_factory):
    root = tmp_path_factory.mktemp("phase2-pki")
    service = PKIService(
        ca_key_dir=root / "private",
        ca_cert_dir=root / "public",
        ca_key_password=CA_PASSWORD,
    )
    service.initialize_hierarchy(now=NOW)
    return service


@pytest.fixture(scope="module")
def issued_material(pki_service):
    generated = pki_service.generate_user_csr(
        common_name="Alice Example",
        email="ALICE@example.test",
        private_key_password=USER_PASSWORD,
    )
    certificate_pem = pki_service.issue_certificate(
        generated.csr_pem,
        valid_until=NOW + timedelta(days=90),
        now=NOW,
    )
    empty_crl = pki_service.generate_crl([], this_update=NOW, next_update=NOW + timedelta(days=7))
    return generated, certificate_pem, empty_crl


def test_root_and_issuing_ca_constraints_and_signatures(pki_service):
    root = x509.load_pem_x509_certificate(pki_service.root_certificate_path.read_bytes())
    issuing = x509.load_pem_x509_certificate(pki_service.issuing_certificate_path.read_bytes())

    assert root.subject == root.issuer
    assert issuing.issuer == root.subject
    assert root.extensions.get_extension_for_class(x509.BasicConstraints).value == (
        x509.BasicConstraints(ca=True, path_length=1)
    )
    assert issuing.extensions.get_extension_for_class(x509.BasicConstraints).value == (
        x509.BasicConstraints(ca=True, path_length=0)
    )
    for certificate in (root, issuing):
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        assert usage.key_cert_sign and usage.crl_sign
        certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        certificate.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        assert certificate.signature_hash_algorithm.name == "sha256"
    assert isinstance(root.public_key(), rsa.RSAPublicKey)
    assert root.public_key().key_size == 3072
    assert isinstance(issuing.public_key(), rsa.RSAPublicKey)
    assert issuing.public_key().key_size == 3072


def test_ca_private_keys_are_encrypted_and_password_protected(pki_service):
    for path in (pki_service.root_key_path, pki_service.issuing_key_path):
        stored = path.read_bytes()
        assert b"BEGIN ENCRYPTED PRIVATE KEY" in stored
        assert b"BEGIN PRIVATE KEY" not in stored
        assert CA_PASSWORD not in stored
        with pytest.raises((TypeError, ValueError)):
            serialization.load_pem_private_key(stored, password=None)
        assert serialization.load_pem_private_key(stored, password=CA_PASSWORD)


def test_csr_validation_and_end_entity_issuance(pki_service, issued_material):
    generated, certificate_pem, _ = issued_material
    csr = pki_service.validate_csr(generated.csr_pem)
    certificate = x509.load_pem_x509_certificate(certificate_pem)

    assert csr.subject == certificate.subject
    assert (
        csr.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)[0].value == "alice@example.test"
    )
    assert certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    assert usage.digital_signature and usage.content_commitment and not usage.key_cert_sign
    eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert DOCUMENT_SIGNING_EKU in eku
    san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.RFC822Name) == ["alice@example.test"]
    certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    certificate.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    assert certificate.not_valid_after_utc <= (
        x509.load_pem_x509_certificate(
            pki_service.issuing_certificate_path.read_bytes()
        ).not_valid_after_utc
    )
    assert b"BEGIN ENCRYPTED PRIVATE KEY" in generated.encrypted_private_key_pem
    assert generated.encrypted_private_key_pem != generated.public_key_pem


def test_certificate_serials_are_unique_and_securely_generated(pki_service, issued_material):
    generated, first_pem, _ = issued_material
    second_pem = pki_service.issue_certificate(
        generated.csr_pem, valid_until=NOW + timedelta(days=90), now=NOW
    )
    first = x509.load_pem_x509_certificate(first_pem)
    second = x509.load_pem_x509_certificate(second_pem)
    assert first.serial_number != second.serial_number
    assert first.serial_number.bit_length() >= 128
    assert second.serial_number.bit_length() >= 128


def test_tampered_csr_is_rejected(pki_service, issued_material):
    generated, _, _ = issued_material
    csr = x509.load_pem_x509_csr(generated.csr_pem)
    tampered = bytearray(csr.public_bytes(serialization.Encoding.DER))
    tampered[-1] ^= 1
    with pytest.raises(CSRValidationError, match="signature"):
        pki_service.validate_csr(bytes(tampered))


def test_csr_requesting_ca_capability_is_rejected(pki_service):
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "Mallory"),
                    x509.NameAttribute(NameOID.EMAIL_ADDRESS, "mallory@example.test"),
                ]
            )
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    with pytest.raises(CSRValidationError, match="CA capability"):
        pki_service.validate_csr(csr.public_bytes(serialization.Encoding.PEM))


def test_weak_csr_key_is_rejected(pki_service):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "Weak Key"),
                    x509.NameAttribute(NameOID.EMAIL_ADDRESS, "weak@example.test"),
                ]
            )
        )
        .sign(key, hashes.SHA256())
    )
    with pytest.raises(CSRValidationError, match="3072"):
        pki_service.validate_csr(csr.public_bytes(serialization.Encoding.PEM))


def test_certificate_cannot_exceed_policy_or_issuing_ca(pki_service, issued_material):
    generated, _, _ = issued_material
    with pytest.raises(CertificateIssuanceError, match="397"):
        pki_service.issue_certificate(
            generated.csr_pem, valid_until=NOW + timedelta(days=398), now=NOW
        )


def test_valid_chain_is_trusted(pki_service, issued_material):
    _, certificate_pem, empty_crl = issued_material
    result = pki_service.validate_chain(
        certificate_pem, at_time=NOW + timedelta(days=1), crl_data=empty_crl
    )
    assert result.cryptographically_valid
    assert result.chain_valid
    assert result.currently_valid
    assert result.usage_valid
    assert result.revocation_checked
    assert not result.revoked
    assert result.trusted
    assert result.reasons == ()


def test_expired_and_malformed_certificates_fail_safely(pki_service, issued_material):
    _, certificate_pem, empty_crl = issued_material
    expired = pki_service.validate_chain(
        certificate_pem, at_time=NOW + timedelta(days=91), crl_data=empty_crl
    )
    assert expired.cryptographically_valid
    assert not expired.currently_valid
    assert not expired.trusted
    assert "end_entity_expired" in expired.reasons

    malformed = pki_service.validate_chain(b"not a certificate", at_time=NOW, crl_data=empty_crl)
    assert not malformed.cryptographically_valid
    assert not malformed.trusted
    assert malformed.reasons == ("malformed_certificate",)


def test_untrusted_but_cryptographically_valid_chain_is_distinguished(tmp_path, pki_service):
    other = PKIService(
        ca_key_dir=tmp_path / "other-private",
        ca_cert_dir=tmp_path / "other-public",
        ca_key_password=CA_PASSWORD,
    )
    hierarchy = other.initialize_hierarchy(now=NOW)
    generated = other.generate_user_csr(
        common_name="Other User",
        email="other@example.test",
        private_key_password=USER_PASSWORD,
    )
    certificate = other.issue_certificate(
        generated.csr_pem, valid_until=NOW + timedelta(days=30), now=NOW
    )
    crl = other.generate_crl([], this_update=NOW, next_update=NOW + timedelta(days=7))
    result = pki_service.validate_chain(
        certificate,
        at_time=NOW + timedelta(days=1),
        crl_data=crl,
        issuing_certificate=hierarchy.issuing_certificate_pem,
        root_certificate=hierarchy.root_certificate_pem,
    )
    assert result.cryptographically_valid
    assert not result.chain_valid
    assert not result.trusted
    assert "untrusted_root" in result.reasons


def test_incorrect_end_entity_usage_is_rejected(pki_service, issued_material):
    generated, _, empty_crl = issued_material
    csr = x509.load_pem_x509_csr(generated.csr_pem)
    issuer = x509.load_pem_x509_certificate(pki_service.issuing_certificate_path.read_bytes())
    issuer_key = serialization.load_pem_private_key(
        pki_service.issuing_key_path.read_bytes(), password=CA_PASSWORD
    )
    bad_usage = x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    bad_certificate = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(minutes=5))
        .not_valid_after(NOW + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(bad_usage, critical=True)
        .add_extension(x509.ExtendedKeyUsage([DOCUMENT_SIGNING_EKU]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
        .sign(issuer_key, hashes.SHA256())
    )
    result = pki_service.validate_chain(
        bad_certificate.public_bytes(serialization.Encoding.PEM),
        at_time=NOW + timedelta(days=1),
        crl_data=empty_crl,
    )
    assert result.cryptographically_valid
    assert not result.usage_valid
    assert not result.trusted
    assert "end_entity_key_usage_invalid" in result.reasons


def test_signed_crl_contains_sorted_serials_and_reason_codes(pki_service, issued_material):
    _, certificate_pem, _ = issued_material
    certificate = x509.load_pem_x509_certificate(certificate_pem)
    entries = [
        RevocationEntry(999, "superseded", NOW - timedelta(hours=2)),
        RevocationEntry(certificate.serial_number, "key_compromise", NOW - timedelta(hours=1)),
    ]
    crl_pem = pki_service.generate_crl(
        entries, this_update=NOW, next_update=NOW + timedelta(days=7)
    )
    crl = x509.load_pem_x509_crl(crl_pem)
    assert [entry.serial_number for entry in crl] == sorted([999, certificate.serial_number])
    revoked = crl.get_revoked_certificate_by_serial_number(certificate.serial_number)
    reason = revoked.extensions.get_extension_for_class(x509.CRLReason).value.reason
    assert reason is x509.ReasonFlags.key_compromise

    result = pki_service.validate_chain(
        certificate_pem, at_time=NOW + timedelta(days=1), crl_data=crl_pem
    )
    assert result.cryptographically_valid
    assert result.chain_valid
    assert result.revocation_checked
    assert result.revoked
    assert not result.trusted
    assert "certificate_revoked" in result.reasons


def test_tampered_crl_fails_closed(pki_service, issued_material):
    _, certificate_pem, empty_crl = issued_material
    parsed = x509.load_pem_x509_crl(empty_crl)
    tampered = bytearray(parsed.public_bytes(serialization.Encoding.DER))
    tampered[-1] ^= 1
    result = pki_service.validate_chain(
        certificate_pem, at_time=NOW + timedelta(days=1), crl_data=bytes(tampered)
    )
    assert not result.cryptographically_valid
    assert not result.revocation_checked
    assert not result.trusted
    assert "invalid_crl" in result.reasons


def test_missing_and_stale_crls_fail_closed_without_mislabeling_signatures(
    pki_service, issued_material
):
    _, certificate_pem, _ = issued_material
    missing = pki_service.validate_chain(
        certificate_pem, at_time=NOW + timedelta(days=1), crl_data=None
    )
    assert missing.cryptographically_valid
    assert missing.chain_valid
    assert not missing.revocation_checked
    assert not missing.trusted
    assert "crl_missing" in missing.reasons

    stale_crl = pki_service.generate_crl(
        [], this_update=NOW - timedelta(days=8), next_update=NOW - timedelta(days=1)
    )
    stale = pki_service.validate_chain(
        certificate_pem, at_time=NOW + timedelta(days=1), crl_data=stale_crl
    )
    assert stale.cryptographically_valid
    assert stale.chain_valid
    assert not stale.revocation_checked
    assert not stale.trusted
    assert "crl_not_current" in stale.reasons


def test_unsupported_revocation_reason_is_rejected(pki_service):
    with pytest.raises(RevocationError, match="Unsupported"):
        pki_service.generate_crl(
            [RevocationEntry(123, "made_up", NOW)],
            this_update=NOW,
            next_update=NOW + timedelta(days=1),
        )


def test_certificate_persistence_and_revocation_lifecycle(app, pki_service, issued_material):
    generated, certificate_pem, _ = issued_material
    user = User(full_name="Alice Example", email="alice-persisted@example.test")
    user.set_password("temporary-test-password")
    administrator = User(
        full_name="CA Administrator", email="ca-admin@example.test", role="ca_admin"
    )
    administrator.set_password("temporary-admin-password")
    db.session.add_all([user, administrator])
    db.session.flush()

    record = persist_issued_certificate(
        user=user,
        reviewer=administrator,
        csr_pem=generated.csr_pem,
        certificate_pem=certificate_pem,
        reviewed_at=NOW,
    )
    db.session.commit()
    assert (
        db.session.query(Certificate).one().certificate_data.startswith(b"-----BEGIN CERTIFICATE")
    )
    assert record.request.status == "approved"
    assert record.status == "active"

    revocation = revoke_persisted_certificate(
        certificate=record,
        administrator=administrator,
        reason="key_compromise",
        revoked_at=NOW + timedelta(hours=1),
    )
    db.session.commit()
    assert record.status == "revoked"
    assert db.session.query(RevocationRecord).one() is revocation
    entries = revocation_entries()
    assert entries == [
        RevocationEntry(
            int(record.serial_number),
            "key_compromise",
            NOW + timedelta(hours=1),
        )
    ]
