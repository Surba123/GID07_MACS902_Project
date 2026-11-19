"""User identity and password verifier metadata."""

from datetime import datetime

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from flask_login import UserMixin
from sqlalchemy import CheckConstraint, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.extensions import db, login_manager
from app.models.common import utc_now

_password_hasher = PasswordHasher(type=Type.ID)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("role IN ('user', 'ca_admin')", name="ck_users_role"),
        CheckConstraint("status IN ('active', 'disabled')", name="ck_users_status"),
        CheckConstraint("length(trim(full_name)) > 0", name="ck_users_full_name"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    full_name: Mapped[str] = mapped_column(String(200), nullable=False)
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="user")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    keys = relationship("KeyRecord", back_populates="user")
    certificate_requests = relationship(
        "CertificateRequest", foreign_keys="CertificateRequest.user_id", back_populates="user"
    )
    certificates = relationship("Certificate", back_populates="user")
    documents = relationship("Document", back_populates="owner")

    @validates("email")
    def normalize_email(self, key: str, address: str) -> str:
        """Normalize case and surrounding space before the unique database check."""
        normalized = address.strip().casefold()
        if not normalized or "@" not in normalized:
            raise ValueError("A valid email address is required")
        return normalized

    def set_password(self, plaintext: str) -> None:
        if not plaintext:
            raise ValueError("Password cannot be empty")
        self.password_hash = _password_hasher.hash(plaintext)

    def verify_password(self, plaintext: str) -> bool:
        try:
            return _password_hasher.verify(self.password_hash, plaintext)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    @property
    def is_active(self) -> bool:
        return self.status == "active"


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    try:
        return db.session.get(User, int(user_id))
    except ValueError:
        return None
