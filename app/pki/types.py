"""Small immutable value objects shared by PKI services and CLI commands."""

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class CAHierarchy:
    root_certificate_pem: bytes
    issuing_certificate_pem: bytes


@dataclass(frozen=True)
class GeneratedCSR:
    encrypted_private_key_pem: bytes
    public_key_pem: bytes
    csr_pem: bytes
    public_key_fingerprint: str


@dataclass(frozen=True)
class RevocationEntry:
    serial_number: int
    reason: str
    revoked_at: datetime


@dataclass(frozen=True)
class CertificateValidationResult:
    cryptographically_valid: bool
    chain_valid: bool
    currently_valid: bool
    usage_valid: bool
    revocation_checked: bool
    revoked: bool
    trusted: bool
    reasons: tuple[str, ...]
    certificate_fingerprint: str | None = None
