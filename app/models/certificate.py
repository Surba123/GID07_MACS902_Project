"""CSR review, issued certificate, and revocation metadata."""

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, LargeBinary, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db
from app.models.common import utc_now


class CertificateRequest(db.Model):
    __tablename__ = "certificate_requests"
    __table_args__ = (
        CheckConstraint("status IN ('pending', 'approved', 'rejected')", name="ck_requests_status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    key_record_id: Mapped[int | None] = mapped_column(
        ForeignKey("key_records.id"), unique=True, index=True
    )
    csr_data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reviewer_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    rejection_reason: Mapped[str | None] = mapped_column(Text)

    user = relationship("User", foreign_keys=[user_id], back_populates="certificate_requests")
    reviewer = relationship("User", foreign_keys=[reviewer_id])
    key_record = relationship("KeyRecord")
    certificate = relationship("Certificate", back_populates="request", uselist=False)


class Certificate(db.Model):
    __tablename__ = "certificates"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'revoked', 'expired')", name="ck_certificates_status"
        ),
        CheckConstraint("valid_until > valid_from", name="ck_certificates_validity"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    request_id: Mapped[int] = mapped_column(
        ForeignKey("certificate_requests.id"), nullable=False, unique=True
    )
    serial_number: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    subject: Mapped[str] = mapped_column(String(500), nullable=False)
    issuer: Mapped[str] = mapped_column(String(500), nullable=False)
    certificate_data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    user = relationship("User", back_populates="certificates")
    request = relationship("CertificateRequest", back_populates="certificate")
    revocation = relationship("RevocationRecord", back_populates="certificate", uselist=False)


class RevocationRecord(db.Model):
    __tablename__ = "revocation_records"
    __table_args__ = (
        CheckConstraint(
            "reason IN ('unspecified', 'key_compromise', 'ca_compromise', "
            "'affiliation_changed', 'superseded', 'cessation_of_operation', "
            "'certificate_hold', 'privilege_withdrawn', 'aa_compromise')",
            name="ck_revocations_reason",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    certificate_id: Mapped[int] = mapped_column(
        ForeignKey("certificates.id"), nullable=False, unique=True
    )
    reason: Mapped[str] = mapped_column(String(200), nullable=False)
    revoked_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    revoked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    certificate = relationship("Certificate", back_populates="revocation")
    administrator = relationship("User", foreign_keys=[revoked_by])
