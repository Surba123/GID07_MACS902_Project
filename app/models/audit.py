"""Security-event metadata only; callers must not include secret-bearing details."""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db
from app.models.common import utc_now


class AuditEvent(db.Model):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    target_type: Mapped[str] = mapped_column(String(80), nullable=False)
    target_id: Mapped[str | None] = mapped_column(String(128))
    outcome: Mapped[str] = mapped_column(String(30), nullable=False)
    safe_detail: Mapped[str | None] = mapped_column(String(1024))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    actor = relationship("User")
