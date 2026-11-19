"""X.509 private-PKI operations built on the cryptography package."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID, ObjectIdentifier

from app.pki.errors import (
    CertificateIssuanceError,
    CSRValidationError,
    PKIConfigurationError,
    PKIStateError,
    RevocationError,
)
from app.pki.types import (
    CAHierarchy,
    CertificateValidationResult,
    GeneratedCSR,
    RevocationEntry,
)

DOCUMENT_SIGNING_EKU = ObjectIdentifier("1.3.6.1.4.1.311.10.3.12")
ALLOWED_REVOCATION_REASONS = {
    "unspecified": x509.ReasonFlags.unspecified,
    "key_compromise": x509.ReasonFlags.key_compromise,
    "ca_compromise": x509.ReasonFlags.ca_compromise,
    "affiliation_changed": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
    "certificate_hold": x509.ReasonFlags.certificate_hold,
    "privilege_withdrawn": x509.ReasonFlags.privilege_withdrawn,
    "aa_compromise": x509.ReasonFlags.aa_compromise,
}

_END_ENTITY_KEY_USAGE = x509.KeyUsage(
    digital_signature=True,
    content_commitment=True,
    key_encipherment=False,
    data_encipherment=False,
    key_agreement=False,
    key_cert_sign=False,
    crl_sign=False,
    encipher_only=False,
    decipher_only=False,
)
_CA_KEY_USAGE = x509.KeyUsage(
    digital_signature=False,
    content_commitment=False,
    key_encipherment=False,
    data_encipherment=False,
    key_agreement=False,
    key_cert_sign=True,
    crl_sign=True,
    encipher_only=False,
    decipher_only=False,
)


class PKIService:
    """Create and validate one local Root -> Issuing CA hierarchy."""

    ROOT_KEY_FILENAME = "root_ca_private_key.pem"
    ROOT_CERT_FILENAME = "root_ca_certificate.pem"
    ISSUING_KEY_FILENAME = "issuing_ca_private_key.pem"
    ISSUING_CERT_FILENAME = "issuing_ca_certificate.pem"
    CRL_FILENAME = "issuing_ca.crl.pem"

    def __init__(
        self,
        *,
        ca_key_dir: Path,
        ca_cert_dir: Path,
        ca_key_password: bytes,
        root_common_name: str = "MACS902 Classroom Root CA",
        issuing_common_name: str = "MACS902 Classroom Issuing CA",
    ) -> None:
        if len(ca_key_password) < 16:
            raise PKIConfigurationError("PKI_CA_KEY_PASSWORD must contain at least 16 characters")
        self.ca_key_dir = Path(ca_key_dir).resolve()
        self.ca_cert_dir = Path(ca_cert_dir).resolve()
        self.ca_key_password = bytes(ca_key_password)
        self.root_common_name = root_common_name.strip()
        self.issuing_common_name = issuing_common_name.strip()
        if not self.root_common_name or not self.issuing_common_name:
            raise PKIConfigurationError("CA common names cannot be empty")

    @classmethod
    def from_config(cls, config: Mapping[str, object]) -> PKIService:
        password = config.get("PKI_CA_KEY_PASSWORD")
        if not isinstance(password, str) or not password:
            raise PKIConfigurationError(
                "PKI_CA_KEY_PASSWORD is required for PKI administration commands"
            )
        return cls(
            ca_key_dir=Path(config["CA_KEY_DIR"]),
            ca_cert_dir=Path(config["CA_CERT_DIR"]),
            ca_key_password=password.encode("utf-8"),
            root_common_name=str(config["PKI_ROOT_CA_NAME"]),
            issuing_common_name=str(config["PKI_ISSUING_CA_NAME"]),
        )

    @property
    def root_key_path(self) -> Path:
        return self.ca_key_dir / self.ROOT_KEY_FILENAME

    @property
    def root_certificate_path(self) -> Path:
        return self.ca_cert_dir / self.ROOT_CERT_FILENAME

    @property
    def issuing_key_path(self) -> Path:
        return self.ca_key_dir / self.ISSUING_KEY_FILENAME

    @property
    def issuing_certificate_path(self) -> Path:
        return self.ca_cert_dir / self.ISSUING_CERT_FILENAME

    @property
    def crl_path(self) -> Path:
        return self.ca_cert_dir / self.CRL_FILENAME

    def initialize_hierarchy(self, *, now: datetime | None = None) -> CAHierarchy:
        """Create the CA hierarchy once, refusing to repair a partial hierarchy silently."""
        paths = (
            self.root_key_path,
            self.root_certificate_path,
            self.issuing_key_path,
            self.issuing_certificate_path,
        )
        existing = [path.exists() for path in paths]
        if all(existing):
            root, issuing = self._load_hierarchy(validate_root_key=True)
            return CAHierarchy(
                root.public_bytes(serialization.Encoding.PEM),
                issuing.public_bytes(serialization.Encoding.PEM),
            )
        if any(existing):
            raise PKIStateError(
                "The CA hierarchy is incomplete; restore or remove it manually "
                "before initialization"
            )

        current = _aware_utc(now or datetime.now(UTC), field="now")
        self.ca_key_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.ca_cert_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

        root_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        root_subject = _ca_name(self.root_common_name)
        root_certificate = (
            x509.CertificateBuilder()
            .subject_name(root_subject)
            .issuer_name(root_subject)
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(current - timedelta(minutes=5))
            .not_valid_after(current + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(_CA_KEY_USAGE, critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
                critical=False,
            )
            .sign(root_key, hashes.SHA256())
        )

        issuing_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        issuing_certificate = (
            x509.CertificateBuilder()
            .subject_name(_ca_name(self.issuing_common_name))
            .issuer_name(root_certificate.subject)
            .public_key(issuing_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(current - timedelta(minutes=5))
            .not_valid_after(
                min(current + timedelta(days=1825), root_certificate.not_valid_after_utc)
            )
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(_CA_KEY_USAGE, critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(issuing_key.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
                critical=False,
            )
            .sign(root_key, hashes.SHA256())
        )

        self._write_private_key(self.root_key_path, root_key)
        self._write_new(
            self.root_certificate_path, root_certificate.public_bytes(serialization.Encoding.PEM)
        )
        self._write_private_key(self.issuing_key_path, issuing_key)
        self._write_new(
            self.issuing_certificate_path,
            issuing_certificate.public_bytes(serialization.Encoding.PEM),
        )
        return CAHierarchy(
            root_certificate.public_bytes(serialization.Encoding.PEM),
            issuing_certificate.public_bytes(serialization.Encoding.PEM),
        )

    def generate_user_csr(
        self, *, common_name: str, email: str, private_key_password: bytes
    ) -> GeneratedCSR:
        """Generate a protected RSA signing key and policy-conforming CSR."""
        if len(private_key_password) < 16:
            raise PKIConfigurationError("The user-key password must contain at least 16 characters")
        subject = _user_name(common_name, email)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_END_ENTITY_KEY_USAGE, critical=True)
            .add_extension(x509.ExtendedKeyUsage([DOCUMENT_SIGNING_EKU]), critical=False)
            .add_extension(
                x509.SubjectAlternativeName([x509.RFC822Name(email.strip().casefold())]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )
        public_der = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        digest = hashes.Hash(hashes.SHA256())
        digest.update(public_der)
        fingerprint = digest.finalize().hex()
        return GeneratedCSR(
            encrypted_private_key_pem=private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(private_key_password),
            ),
            public_key_pem=private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            csr_pem=csr.public_bytes(serialization.Encoding.PEM),
            public_key_fingerprint=fingerprint,
        )

    def validate_csr(self, csr_data: bytes) -> x509.CertificateSigningRequest:
        """Parse a CSR and enforce signature, subject, key, and extension policy."""
        try:
            csr = _load_csr(csr_data)
        except (TypeError, ValueError) as error:
            raise CSRValidationError("CSR data is not valid PEM or DER") from error
        if not csr.is_signature_valid:
            raise CSRValidationError("CSR signature is invalid")

        _validate_user_subject(csr.subject)
        public_key = csr.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 3072:
            raise CSRValidationError("CSR public key must be RSA with at least 3072 bits")

        allowed_oids = {
            ExtensionOID.BASIC_CONSTRAINTS,
            ExtensionOID.KEY_USAGE,
            ExtensionOID.EXTENDED_KEY_USAGE,
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
        }
        for extension in csr.extensions:
            if extension.oid not in allowed_oids:
                raise CSRValidationError(f"CSR requests an unsupported extension: {extension.oid}")
            if (
                extension.oid == ExtensionOID.BASIC_CONSTRAINTS
                and extension.value != x509.BasicConstraints(ca=False, path_length=None)
            ):
                raise CSRValidationError("CSR cannot request CA capability")
            if extension.oid == ExtensionOID.KEY_USAGE and extension.value != _END_ENTITY_KEY_USAGE:
                raise CSRValidationError("CSR requests key usage outside document signing")
            if (
                extension.oid == ExtensionOID.EXTENDED_KEY_USAGE
                and extension.value != x509.ExtendedKeyUsage([DOCUMENT_SIGNING_EKU])
            ):
                raise CSRValidationError("CSR requests an unsupported extended key usage")
            if extension.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                emails = extension.value.get_values_for_type(x509.RFC822Name)
                subject_email = csr.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)[0].value
                if emails != [subject_email.casefold()] or len(extension.value) != 1:
                    raise CSRValidationError("CSR subject alternative name must match its email")
        return csr

    def issue_certificate(
        self, csr_data: bytes, *, valid_until: datetime, now: datetime | None = None
    ) -> bytes:
        """Issue a constrained document-signing certificate from the Issuing CA."""
        csr = self.validate_csr(csr_data)
        current = _aware_utc(now or datetime.now(UTC), field="now")
        requested_end = _aware_utc(valid_until, field="valid_until")
        if requested_end <= current:
            raise CertificateIssuanceError("Certificate validity must end after issuance")
        if requested_end > current + timedelta(days=397):
            raise CertificateIssuanceError("End-entity certificate validity cannot exceed 397 days")

        _, issuer_certificate = self._load_hierarchy()
        issuer_key = self._load_private_key(self.issuing_key_path)
        if current < issuer_certificate.not_valid_before_utc:
            raise CertificateIssuanceError("The Issuing CA is not yet valid")
        if requested_end > issuer_certificate.not_valid_after_utc:
            raise CertificateIssuanceError("Certificate cannot outlive the Issuing CA")
        subject_email = csr.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)[
            0
        ].value.casefold()

        certificate = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(issuer_certificate.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(current - timedelta(minutes=5))
            .not_valid_after(requested_end)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_END_ENTITY_KEY_USAGE, critical=True)
            .add_extension(x509.ExtendedKeyUsage([DOCUMENT_SIGNING_EKU]), critical=False)
            .add_extension(
                x509.SubjectAlternativeName([x509.RFC822Name(subject_email)]),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                critical=False,
            )
            .sign(issuer_key, hashes.SHA256())
        )
        return certificate.public_bytes(serialization.Encoding.PEM)

    def generate_crl(
        self,
        revocations: Iterable[RevocationEntry],
        *,
        this_update: datetime | None = None,
        next_update: datetime | None = None,
    ) -> bytes:
        """Create a signed, serial-sorted full CRL for deterministic test inputs."""
        current = _aware_utc(this_update or datetime.now(UTC), field="this_update")
        next_time = _aware_utc(next_update or current + timedelta(days=7), field="next_update")
        if next_time <= current:
            raise RevocationError("CRL next_update must be after this_update")
        _, issuer_certificate = self._load_hierarchy()
        issuer_key = self._load_private_key(self.issuing_key_path)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(issuer_certificate.subject)
            .last_update(current)
            .next_update(next_time)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                critical=False,
            )
        )
        seen: set[int] = set()
        for entry in sorted(revocations, key=lambda item: item.serial_number):
            if entry.serial_number <= 0 or entry.serial_number in seen:
                raise RevocationError("CRL serial numbers must be positive and unique")
            seen.add(entry.serial_number)
            try:
                reason = ALLOWED_REVOCATION_REASONS[entry.reason]
            except KeyError as error:
                raise RevocationError(f"Unsupported revocation reason: {entry.reason}") from error
            revoked_certificate = (
                x509.RevokedCertificateBuilder()
                .serial_number(entry.serial_number)
                .revocation_date(_aware_utc(entry.revoked_at, field="revoked_at"))
                .add_extension(x509.CRLReason(reason), critical=False)
                .build()
            )
            builder = builder.add_revoked_certificate(revoked_certificate)
        crl = builder.sign(issuer_key, hashes.SHA256())
        return crl.public_bytes(serialization.Encoding.PEM)

    def validate_chain(
        self,
        certificate_data: bytes,
        *,
        at_time: datetime,
        crl_data: bytes | None,
        issuing_certificate: bytes | None = None,
        root_certificate: bytes | None = None,
    ) -> CertificateValidationResult:
        """Validate certificate mechanics and the local trust decision separately."""
        checked_at = _aware_utc(at_time, field="at_time")
        reasons: list[str] = []

        try:
            certificate = _load_certificate(certificate_data)
            configured_root, configured_issuer = self._load_hierarchy()
            issuer = (
                _load_certificate(issuing_certificate)
                if issuing_certificate is not None
                else configured_issuer
            )
            root = (
                _load_certificate(root_certificate)
                if root_certificate is not None
                else configured_root
            )
        except (TypeError, ValueError, PKIStateError):
            return CertificateValidationResult(
                False, False, False, False, False, False, False, ("malformed_certificate",)
            )

        fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
        certificate_signatures_valid = True
        for child, parent, reason in (
            (certificate, issuer, "invalid_end_entity_signature"),
            (issuer, root, "invalid_issuing_ca_signature"),
            (root, root, "invalid_root_signature"),
        ):
            try:
                _verify_certificate_signature(child, parent)
            except (InvalidSignature, TypeError, ValueError):
                certificate_signatures_valid = False
                _add_reason(reasons, reason)

        issuer_relationships_valid = True
        if certificate.issuer != issuer.subject:
            issuer_relationships_valid = False
            _add_reason(reasons, "end_entity_issuer_mismatch")
        if issuer.issuer != root.subject:
            issuer_relationships_valid = False
            _add_reason(reasons, "issuing_ca_issuer_mismatch")
        if root.issuer != root.subject:
            issuer_relationships_valid = False
            _add_reason(reasons, "root_not_self_issued")

        constraints_valid = _validate_certificate_constraints(certificate, issuer, root, reasons)
        identifiers_valid = _validate_key_identifier_links(certificate, issuer, root, reasons)
        validity_nesting_valid = True
        if certificate.not_valid_after_utc > issuer.not_valid_after_utc:
            validity_nesting_valid = False
            _add_reason(reasons, "end_entity_outlives_issuing_ca")
        if issuer.not_valid_after_utc > root.not_valid_after_utc:
            validity_nesting_valid = False
            _add_reason(reasons, "issuing_ca_outlives_root")
        trusted_root = root.fingerprint(hashes.SHA256()) == configured_root.fingerprint(
            hashes.SHA256()
        )
        if not trusted_root:
            _add_reason(reasons, "untrusted_root")

        currently_valid = True
        for current_certificate, label in (
            (certificate, "end_entity"),
            (issuer, "issuing_ca"),
            (root, "root"),
        ):
            if checked_at < current_certificate.not_valid_before_utc:
                currently_valid = False
                _add_reason(reasons, f"{label}_not_yet_valid")
            if checked_at > current_certificate.not_valid_after_utc:
                currently_valid = False
                _add_reason(reasons, f"{label}_expired")

        revocation_checked = False
        revoked = False
        crl_signature_valid = True
        if crl_data is None:
            _add_reason(reasons, "crl_missing")
        else:
            try:
                crl = _load_crl(crl_data)
                if crl.issuer != issuer.subject:
                    raise RevocationError("CRL issuer does not match the Issuing CA")
                _verify_crl_signature(crl, issuer)
                crl_aki = crl.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
                issuer_ski = issuer.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier
                ).value
                if crl_aki.key_identifier != issuer_ski.digest:
                    raise RevocationError("CRL authority key identifier does not match the issuer")
            except (InvalidSignature, TypeError, ValueError, RevocationError):
                crl_signature_valid = False
                _add_reason(reasons, "invalid_crl")
            else:
                if checked_at < crl.last_update_utc or checked_at > crl.next_update_utc:
                    _add_reason(reasons, "crl_not_current")
                else:
                    revocation_checked = True
                    revoked = (
                        crl.get_revoked_certificate_by_serial_number(certificate.serial_number)
                        is not None
                    )
                    if revoked:
                        _add_reason(reasons, "certificate_revoked")

        cryptographically_valid = certificate_signatures_valid and crl_signature_valid
        chain_valid = (
            certificate_signatures_valid
            and issuer_relationships_valid
            and constraints_valid
            and identifiers_valid
            and validity_nesting_valid
            and trusted_root
        )
        usage_valid = constraints_valid
        trusted = (
            cryptographically_valid
            and chain_valid
            and currently_valid
            and usage_valid
            and revocation_checked
            and not revoked
        )
        return CertificateValidationResult(
            cryptographically_valid=cryptographically_valid,
            chain_valid=chain_valid,
            currently_valid=currently_valid,
            usage_valid=usage_valid,
            revocation_checked=revocation_checked,
            revoked=revoked,
            trusted=trusted,
            reasons=tuple(reasons),
            certificate_fingerprint=fingerprint,
        )

    def write_crl(self, crl_pem: bytes) -> Path:
        """Publish a public CRL without overwriting it through a partial write."""
        try:
            crl = _load_crl(crl_pem)
        except (TypeError, ValueError) as error:
            raise RevocationError("CRL data is not valid PEM or DER") from error
        _, issuer = self._load_hierarchy()
        try:
            if crl.issuer != issuer.subject:
                raise RevocationError("CRL issuer does not match the Issuing CA")
            _verify_crl_signature(crl, issuer)
        except (InvalidSignature, TypeError, ValueError) as error:
            raise RevocationError("CRL signature is invalid") from error
        self.ca_cert_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = self.crl_path.with_suffix(".tmp")
        temporary.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
        temporary.replace(self.crl_path)
        return self.crl_path

    def _load_hierarchy(
        self, *, validate_root_key: bool = False
    ) -> tuple[x509.Certificate, x509.Certificate]:
        try:
            root = _load_certificate(self.root_certificate_path.read_bytes())
            issuing = _load_certificate(self.issuing_certificate_path.read_bytes())
            issuing_key = self._load_private_key(self.issuing_key_path)
            root_key = self._load_private_key(self.root_key_path) if validate_root_key else None
        except (OSError, TypeError, ValueError) as error:
            raise PKIStateError("The CA hierarchy cannot be loaded") from error
        if root_key is not None and _public_key_bytes(root.public_key()) != _public_key_bytes(
            root_key.public_key()
        ):
            raise PKIStateError("Root CA private key does not match its certificate")
        if _public_key_bytes(issuing.public_key()) != _public_key_bytes(issuing_key.public_key()):
            raise PKIStateError("Issuing CA private key does not match its certificate")
        try:
            _verify_certificate_signature(root, root)
            _verify_certificate_signature(issuing, root)
            _validate_loaded_ca(root, expected_path_length=1, parent=root)
            _validate_loaded_ca(issuing, expected_path_length=0, parent=root)
        except (InvalidSignature, TypeError, ValueError, x509.ExtensionNotFound) as error:
            raise PKIStateError("The CA hierarchy fails integrity or policy validation") from error
        if root.subject != root.issuer or issuing.issuer != root.subject:
            raise PKIStateError("The CA hierarchy contains invalid issuer relationships")
        return root, issuing

    def _load_private_key(self, path: Path) -> rsa.RSAPrivateKey:
        key = serialization.load_pem_private_key(path.read_bytes(), password=self.ca_key_password)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise PKIStateError("CA private key is not RSA")
        return key

    def _write_private_key(self, path: Path, key: rsa.RSAPrivateKey) -> None:
        self._write_new(
            path,
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(self.ca_key_password),
            ),
            private=True,
        )

    @staticmethod
    def _write_new(path: Path, data: bytes, *, private: bool = False) -> None:
        try:
            with path.open("xb") as stream:
                stream.write(data)
            path.chmod(0o600 if private else 0o644)
        except FileExistsError as error:
            raise PKIStateError(f"Refusing to overwrite existing PKI file: {path.name}") from error


def _aware_utc(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")
    return value.astimezone(UTC)


def _ca_name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MACS902 Classroom Project"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _user_name(common_name: str, email: str) -> x509.Name:
    normalized_name = common_name.strip()
    normalized_email = email.strip().casefold()
    if not normalized_name or len(normalized_name) > 200:
        raise CSRValidationError("Common name must contain 1 to 200 characters")
    if not normalized_email or len(normalized_email) > 320 or "@" not in normalized_email:
        raise CSRValidationError("A valid email subject field is required")
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, normalized_name),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, normalized_email),
        ]
    )


def _validate_user_subject(subject: x509.Name) -> None:
    allowed = {NameOID.COMMON_NAME, NameOID.EMAIL_ADDRESS}
    if any(attribute.oid not in allowed for attribute in subject):
        raise CSRValidationError("CSR subject contains an unsupported field")
    common_names = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    emails = subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
    if len(common_names) != 1 or len(emails) != 1:
        raise CSRValidationError("CSR subject requires exactly one common name and email")
    _user_name(common_names[0].value, emails[0].value)


def _load_csr(data: bytes) -> x509.CertificateSigningRequest:
    try:
        return x509.load_pem_x509_csr(data)
    except ValueError:
        return x509.load_der_x509_csr(data)


def _load_certificate(data: bytes) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError:
        return x509.load_der_x509_certificate(data)


def _load_crl(data: bytes) -> x509.CertificateRevocationList:
    try:
        return x509.load_pem_x509_crl(data)
    except ValueError:
        return x509.load_der_x509_crl(data)


def _verify_certificate_signature(child: x509.Certificate, parent: x509.Certificate) -> None:
    public_key = parent.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Only RSA CA keys are supported")
    public_key.verify(
        child.signature,
        child.tbs_certificate_bytes,
        child.signature_algorithm_parameters,
        child.signature_hash_algorithm,
    )


def _verify_crl_signature(crl: x509.CertificateRevocationList, issuer: x509.Certificate) -> None:
    public_key = issuer.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Only RSA CA keys are supported")
    public_key.verify(
        crl.signature,
        crl.tbs_certlist_bytes,
        crl.signature_algorithm_parameters,
        crl.signature_hash_algorithm,
    )


def _public_key_bytes(public_key) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _validate_certificate_constraints(
    certificate: x509.Certificate,
    issuer: x509.Certificate,
    root: x509.Certificate,
    reasons: list[str],
) -> bool:
    valid = True
    expected_constraints = (
        (certificate, False, None, "end_entity"),
        (issuer, True, 0, "issuing_ca"),
        (root, True, 1, "root"),
    )
    for current, ca, path_length, label in expected_constraints:
        try:
            constraints = current.extensions.get_extension_for_class(x509.BasicConstraints)
            if not constraints.critical or constraints.value != x509.BasicConstraints(
                ca=ca, path_length=path_length
            ):
                raise ValueError
        except (x509.ExtensionNotFound, ValueError):
            valid = False
            _add_reason(reasons, f"{label}_basic_constraints_invalid")

    for current, expected, label in (
        (certificate, _END_ENTITY_KEY_USAGE, "end_entity"),
        (issuer, _CA_KEY_USAGE, "issuing_ca"),
        (root, _CA_KEY_USAGE, "root"),
    ):
        try:
            usage = current.extensions.get_extension_for_class(x509.KeyUsage)
            if not usage.critical or usage.value != expected:
                raise ValueError
        except (x509.ExtensionNotFound, ValueError):
            valid = False
            _add_reason(reasons, f"{label}_key_usage_invalid")

    try:
        eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if eku != x509.ExtendedKeyUsage([DOCUMENT_SIGNING_EKU]):
            raise ValueError
    except (x509.ExtensionNotFound, ValueError):
        valid = False
        _add_reason(reasons, "end_entity_extended_key_usage_invalid")

    try:
        _validate_user_subject(certificate.subject)
        email = certificate.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)[
            0
        ].value.casefold()
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if san.get_values_for_type(x509.RFC822Name) != [email] or len(san) != 1:
            raise ValueError
    except (CSRValidationError, x509.ExtensionNotFound, ValueError):
        valid = False
        _add_reason(reasons, "end_entity_identity_fields_invalid")

    for current, label in ((certificate, "end_entity"), (issuer, "issuing_ca"), (root, "root")):
        try:
            current.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
            current.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        except x509.ExtensionNotFound:
            valid = False
            _add_reason(reasons, f"{label}_key_identifier_missing")
    return valid


def _validate_key_identifier_links(
    certificate: x509.Certificate,
    issuer: x509.Certificate,
    root: x509.Certificate,
    reasons: list[str],
) -> bool:
    valid = True
    for child, parent, label in (
        (certificate, issuer, "end_entity"),
        (issuer, root, "issuing_ca"),
        (root, root, "root"),
    ):
        try:
            authority = child.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
            subject = parent.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            if authority.key_identifier != subject.digest:
                raise ValueError
        except (x509.ExtensionNotFound, ValueError):
            valid = False
            _add_reason(reasons, f"{label}_authority_key_identifier_mismatch")
    return valid


def _validate_loaded_ca(
    certificate: x509.Certificate,
    *,
    expected_path_length: int,
    parent: x509.Certificate,
) -> None:
    """Reject stored CA material that does not satisfy this project's policy."""
    public_key = certificate.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 3072:
        raise ValueError("CA public key does not satisfy policy")
    constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
    usage = certificate.extensions.get_extension_for_class(x509.KeyUsage)
    subject_key = certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    authority_key = certificate.extensions.get_extension_for_class(
        x509.AuthorityKeyIdentifier
    ).value
    parent_subject_key = parent.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    if (
        not constraints.critical
        or constraints.value != x509.BasicConstraints(ca=True, path_length=expected_path_length)
        or not usage.critical
        or usage.value != _CA_KEY_USAGE
        or authority_key.key_identifier != parent_subject_key.digest
        or subject_key.digest != x509.SubjectKeyIdentifier.from_public_key(public_key).digest
    ):
        raise ValueError("CA extensions do not satisfy policy")


def _add_reason(reasons: list[str], reason: str) -> None:
    if reason not in reasons:
        reasons.append(reason)
