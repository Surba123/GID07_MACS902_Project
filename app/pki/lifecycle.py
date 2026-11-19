"""Database persistence for certificate requests, certificates, and revocations."""

from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from app.extensions import db
from app.models import Certificate, CertificateRequest, RevocationRecord, User
from app.pki.errors import CertificateIssuanceError, RevocationError
from app.pki.service import ALLOWED_REVOCATION_REASONS
from app.pki.types import RevocationEntry


def persist_issued_certificate(
    *,
    user: User,
    reviewer: User | None,
    csr_pem: bytes,
    certificate_pem: bytes,
    reviewed_at: datetime | None = None,
) -> Certificate:
    """Persist public PKI material after checking that the CSR and certificate agree."""
    try:
        csr = x509.load_pem_x509_csr(csr_pem)
        certificate = x509.load_pem_x509_certificate(certificate_pem)
    except ValueError as error:
        raise CertificateIssuanceError("Issued certificate or CSR is malformed") from error
    csr_public = csr.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    certificate_public = certificate.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if csr.subject != certificate.subject or csr_public != certificate_public:
        raise CertificateIssuanceError("Issued certificate does not match the approved CSR")

    decision_time = (reviewed_at or datetime.now(UTC)).astimezone(UTC)
    request = CertificateRequest(
        user=user,
        csr_data=csr_pem,
        status="approved",
        reviewed_at=decision_time,
        reviewer=reviewer,
    )
    record = Certificate(
        user=user,
        request=request,
        serial_number=str(certificate.serial_number),
        subject=certificate.subject.rfc4514_string(),
        issuer=certificate.issuer.rfc4514_string(),
        certificate_data=certificate_pem,
        fingerprint=certificate.fingerprint(hashes.SHA256()).hex(),
        valid_from=certificate.not_valid_before_utc,
        valid_until=certificate.not_valid_after_utc,
        status="active",
    )
    db.session.add_all([request, record])
    db.session.flush()
    return record


def revoke_persisted_certificate(
    *,
    certificate: Certificate,
    administrator: User,
    reason: str,
    revoked_at: datetime | None = None,
) -> RevocationRecord:
    """Apply one irreversible full-CRL revocation to an active certificate."""
    if administrator.role != "ca_admin":
        raise RevocationError("Certificate revocation requires a CA administrator")
    if reason not in ALLOWED_REVOCATION_REASONS:
        raise RevocationError(f"Unsupported revocation reason: {reason}")
    if certificate.status == "revoked" or certificate.revocation is not None:
        raise RevocationError("Certificate is already revoked")
    revocation = RevocationRecord(
        certificate=certificate,
        administrator=administrator,
        reason=reason,
        revoked_at=(revoked_at or datetime.now(UTC)).astimezone(UTC),
    )
    certificate.status = "revoked"
    db.session.add(revocation)
    db.session.flush()
    return revocation


def revocation_entries() -> list[RevocationEntry]:
    """Return persisted revocations in stable serial-number order for a full CRL."""
    rows = db.session.query(RevocationRecord).join(Certificate).all()
    entries = [
        RevocationEntry(
            serial_number=int(row.certificate.serial_number),
            reason=row.reason,
            revoked_at=_as_utc(row.revoked_at),
        )
        for row in rows
    ]
    return sorted(entries, key=lambda item: item.serial_number)


def _as_utc(value: datetime) -> datetime:
    # SQLite may return a naive value even for a timezone-aware SQLAlchemy column.
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
