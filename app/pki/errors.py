"""Controlled errors raised by the PKI service boundary."""


class PKIError(Exception):
    """Base class for expected PKI failures safe to report without key material."""


class PKIConfigurationError(PKIError):
    """Required PKI paths or encryption material are unavailable."""


class PKIStateError(PKIError):
    """The on-disk CA hierarchy is missing, partial, or inconsistent."""


class CSRValidationError(PKIError):
    """A CSR is malformed, cryptographically invalid, or outside policy."""


class CertificateIssuanceError(PKIError):
    """A certificate cannot be issued under the configured policy."""


class RevocationError(PKIError):
    """A revocation request or CRL is invalid."""
