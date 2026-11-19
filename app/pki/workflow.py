"""Authenticated user certificate request and administrator decision workflow."""

import secrets
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from app.crypto.key_protection import protect_private_key
from app.extensions import db
from app.models import AuditEvent, Certificate, CertificateRequest, KeyRecord, User
from app.pki.service import PKIService


class CertificateWorkflowError(ValueError):
    """A safe certificate-workflow failure."""


def create_signing_request(*, user: User, password: str, pki: PKIService) -> CertificateRequest:
    """Generate an RSA key/CSR via Phase 2 and wrap the key in the Phase 4 envelope."""
    if not user.verify_password(password):
        raise CertificateWorkflowError("The password is incorrect")
    if db.session.query(CertificateRequest).filter_by(user_id=user.id, status="pending").first():
        raise CertificateWorkflowError("A signing-certificate request is already pending")
    if db.session.query(Certificate).filter_by(user_id=user.id, status="active").first():
        raise CertificateWorkflowError("An active signing certificate already exists")
    temporary_password = secrets.token_bytes(32)
    generated = pki.generate_user_csr(
        common_name=user.full_name,
        email=user.email,
        private_key_password=temporary_password,
    )
    private_key = serialization.load_pem_private_key(
        generated.encrypted_private_key_pem, password=temporary_password
    )
    raw_private = private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    protected = protect_private_key(raw_private, password, purpose="signing")
    key_record = KeyRecord(
        user=user,
        purpose="signing",
        algorithm="RSA-3072",
        public_key_data=generated.public_key_pem,
        public_key_fingerprint=generated.public_key_fingerprint,
        encrypted_private_key_data=protected.ciphertext,
        private_key_kdf=protected.kdf,
        private_key_salt=protected.salt,
        private_key_nonce=protected.nonce,
        status="pending",
    )
    request = CertificateRequest(user=user, key_record=key_record, csr_data=generated.csr_pem)
    db.session.add_all(
        [
            key_record,
            request,
            AuditEvent(
                actor=user,
                action="certificate_requested",
                target_type="certificate_request",
                outcome="success",
            ),
        ]
    )
    db.session.flush()
    return request


def approve_request(
    *, request: CertificateRequest, administrator: User, pki: PKIService, valid_days: int = 90
) -> Certificate:
    if administrator.role != "ca_admin" or administrator.status != "active":
        raise CertificateWorkflowError("Administrator privileges are required")
    if request.status != "pending" or request.key_record is None:
        raise CertificateWorkflowError("The certificate request is not pending")
    now = datetime.now(UTC)
    certificate_pem = pki.issue_certificate(
        request.csr_data, valid_until=now + timedelta(days=valid_days), now=now
    )
    parsed = x509.load_pem_x509_certificate(certificate_pem)
    request.status = "approved"
    request.reviewed_at = now
    request.reviewer = administrator
    request.key_record.status = "active"
    certificate = Certificate(
        user=request.user,
        request=request,
        serial_number=str(parsed.serial_number),
        subject=parsed.subject.rfc4514_string(),
        issuer=parsed.issuer.rfc4514_string(),
        certificate_data=certificate_pem,
        fingerprint=parsed.fingerprint(hashes.SHA256()).hex(),
        valid_from=parsed.not_valid_before_utc,
        valid_until=parsed.not_valid_after_utc,
    )
    db.session.add_all(
        [
            certificate,
            AuditEvent(
                actor=administrator,
                action="certificate_issued",
                target_type="certificate_request",
                target_id=str(request.id),
                outcome="success",
                safe_detail=f"user_id={request.user_id}",
            ),
        ]
    )
    db.session.flush()
    return certificate


def reject_request(*, request: CertificateRequest, administrator: User, reason: str) -> None:
    if administrator.role != "ca_admin" or request.status != "pending":
        raise CertificateWorkflowError("The certificate request cannot be rejected")
    clean_reason = reason.strip()
    if not clean_reason or len(clean_reason) > 500:
        raise CertificateWorkflowError("A concise rejection reason is required")
    request.status = "rejected"
    request.reviewed_at = datetime.now(UTC)
    request.reviewer = administrator
    request.rejection_reason = clean_reason
    if request.key_record:
        request.key_record.status = "retired"
    db.session.add(
        AuditEvent(
            actor=administrator,
            action="certificate_rejected",
            target_type="certificate_request",
            target_id=str(request.id),
            outcome="success",
        )
    )
