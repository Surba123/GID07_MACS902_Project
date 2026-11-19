"""Metadata fields reserved for Phase 2 protected key material."""

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db
from app.models.common import utc_now


class KeyRecord(db.Model):
    __tablename__ = "key_records"
    __table_args__ = (
        CheckConstraint("purpose IN ('signing', 'key_agreement')", name="ck_keys_purpose"),
        CheckConstraint(
            "status IN ('pending', 'active', 'retired', 'compromised')", name="ck_keys_status"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    purpose: Mapped[str] = mapped_column(String(30), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(80), nullable=False)
    public_key_data: Mapped[bytes | None] = mapped_column(LargeBinary)
    public_key_fingerprint: Mapped[str | None] = mapped_column(String(128), unique=True)
    encrypted_private_key_data: Mapped[bytes | None] = mapped_column(LargeBinary)
    private_key_kdf: Mapped[str | None] = mapped_column(String(80))
    private_key_salt: Mapped[bytes | None] = mapped_column(LargeBinary)
    private_key_nonce: Mapped[bytes | None] = mapped_column(LargeBinary)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    user = relationship("User", back_populates="keys")
