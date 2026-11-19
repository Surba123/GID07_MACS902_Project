"""Metadata for stored documents, detached signatures and encrypted packages."""

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db
from app.models.common import utc_now


class Document(db.Model):
    __tablename__ = "documents"
    __table_args__ = (
        CheckConstraint("status IN ('stored', 'deleted')", name="ck_documents_status"),
        CheckConstraint("length(sha256_hash) = 64", name="ck_documents_sha256_length"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    media_type: Mapped[str] = mapped_column(String(100), nullable=False, default="text/plain")
    byte_length: Mapped[int] = mapped_column(nullable=False, default=0)
    storage_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="stored")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    owner = relationship("User", back_populates="documents")
    signatures = relationship("SignatureRecord", back_populates="document")


class SignatureRecord(db.Model):
    __tablename__ = "signature_records"
    __table_args__ = (
        UniqueConstraint("public_id", name="uq_signature_records_public_id"),
        Index("ix_signature_records_public_id", "public_id", unique=True),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    public_id: Mapped[str] = mapped_column(String(36), nullable=False)
    document_id: Mapped[int] = mapped_column(ForeignKey("documents.id"), nullable=False, index=True)
    signer_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    certificate_id: Mapped[int] = mapped_column(
        ForeignKey("certificates.id"), nullable=False, index=True
    )
    manifest_data: Mapped[str] = mapped_column(Text, nullable=False)
    signature_data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    package_data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    algorithm: Mapped[str] = mapped_column(String(80), nullable=False)
    package_version: Mapped[str] = mapped_column(String(20), nullable=False)
    signing_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    document = relationship("Document", back_populates="signatures")
    signer = relationship("User", foreign_keys=[signer_id])
    certificate = relationship("Certificate")


class EncryptedDocument(db.Model):
    __tablename__ = "encrypted_documents"
    __table_args__ = (
        CheckConstraint("status IN ('stored', 'deleted')", name="ck_encrypted_documents_status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    public_id: Mapped[str] = mapped_column(
        String(36), nullable=False, unique=True, index=True, default=lambda: str(uuid.uuid4())
    )
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    recipient_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    storage_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    original_filename: Mapped[str] = mapped_column(
        String(255), nullable=False, default="legacy.bin"
    )
    media_type: Mapped[str] = mapped_column(
        String(100), nullable=False, default="application/octet-stream"
    )
    byte_length: Mapped[int] = mapped_column(nullable=False, default=0)
    package_version: Mapped[str] = mapped_column(String(20), nullable=False)
    algorithm_metadata: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="stored")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    sender = relationship("User", foreign_keys=[sender_id])
    recipient = relationship("User", foreign_keys=[recipient_id])
