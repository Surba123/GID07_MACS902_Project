"""Typed contract for the Phase 2 private-PKI implementation."""

from datetime import datetime
from typing import Protocol

from cryptography import x509

from app.pki.types import (
    CAHierarchy,
    CertificateValidationResult,
    GeneratedCSR,
    RevocationEntry,
)


class PKIServiceProtocol(Protocol):
    def initialize_hierarchy(self, *, now: datetime | None = None) -> CAHierarchy: ...

    def generate_user_csr(
        self, *, common_name: str, email: str, private_key_password: bytes
    ) -> GeneratedCSR: ...

    def validate_csr(self, csr_data: bytes) -> x509.CertificateSigningRequest: ...

    def issue_certificate(
        self, csr_data: bytes, *, valid_until: datetime, now: datetime | None = None
    ) -> bytes: ...

    def generate_crl(
        self,
        revocations: list[RevocationEntry],
        *,
        this_update: datetime | None = None,
        next_update: datetime | None = None,
    ) -> bytes: ...

    def validate_chain(
        self,
        certificate_data: bytes,
        *,
        at_time: datetime,
        crl_data: bytes | None,
        issuing_certificate: bytes | None = None,
        root_certificate: bytes | None = None,
    ) -> CertificateValidationResult: ...
