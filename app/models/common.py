"""Shared UTC timestamp convention for SQLite-backed records."""

from datetime import UTC, datetime


def utc_now() -> datetime:
    return datetime.now(UTC)
