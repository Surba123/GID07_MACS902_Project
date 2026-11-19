"""Operator-only Flask CLI commands for local Phase 2 PKI administration."""

from datetime import UTC, datetime, timedelta

import click
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from flask import current_app

from app.extensions import db
from app.models import Certificate, KeyRecord, User
from app.pki.errors import PKIError
from app.pki.lifecycle import (
    persist_issued_certificate,
    revocation_entries,
    revoke_persisted_certificate,
)
from app.pki.service import ALLOWED_REVOCATION_REASONS, PKIService


@click.group("pki")
def pki_cli() -> None:
    """Manage the local classroom PKI without exposing private key bytes."""


@pki_cli.command("init")
def initialize_pki() -> None:
    """Create or validate the protected Root and Issuing CA hierarchy."""
    try:
        service = PKIService.from_config(current_app.config)
        hierarchy = service.initialize_hierarchy()
        root = x509.load_pem_x509_certificate(hierarchy.root_certificate_pem)
        issuing = x509.load_pem_x509_certificate(hierarchy.issuing_certificate_pem)
    except PKIError as error:
        raise click.ClickException(str(error)) from error
    click.echo(f"Root CA SHA-256 fingerprint: {root.fingerprint(hashes.SHA256()).hex()}")
    click.echo(f"Issuing CA SHA-256 fingerprint: {issuing.fingerprint(hashes.SHA256()).hex()}")
    click.echo("PKI hierarchy is ready; private key material was not displayed.")


@pki_cli.command("issue-development-certificate")
@click.option("--name", required=True, help="Certificate subject common name.")
@click.option("--email", required=True, help="Certificate subject email.")
@click.option("--valid-days", type=click.IntRange(1, 397), default=90, show_default=True)
def issue_development_certificate(name: str, email: str, valid_days: int) -> None:
    """Issue a disabled development user's certificate for local PKI testing."""
    password = current_app.config.get("PKI_DEVELOPMENT_USER_KEY_PASSWORD")
    if not isinstance(password, str) or len(password) < 16:
        raise click.ClickException(
            "PKI_DEVELOPMENT_USER_KEY_PASSWORD with at least 16 characters is required"
        )
    try:
        service = PKIService.from_config(current_app.config)
        service.initialize_hierarchy()
        generated = service.generate_user_csr(
            common_name=name, email=email, private_key_password=password.encode("utf-8")
        )
        now = datetime.now(UTC)
        certificate_pem = service.issue_certificate(
            generated.csr_pem, valid_until=now + timedelta(days=valid_days), now=now
        )
        user = db.session.query(User).filter_by(email=email.strip().casefold()).one_or_none()
        if user is None:
            user = User(full_name=name, email=email, status="disabled")
            # The Phase 2 CLI account cannot be used to log in; its random password is discarded.
            import secrets

            user.set_password(secrets.token_urlsafe(48))
            db.session.add(user)
            db.session.flush()
        key_record = KeyRecord(
            user=user,
            purpose="signing",
            algorithm="RSA-3072",
            public_key_data=generated.public_key_pem,
            public_key_fingerprint=generated.public_key_fingerprint,
            encrypted_private_key_data=generated.encrypted_private_key_pem,
            private_key_kdf="PKCS8-BestAvailableEncryption",
            status="active",
        )
        db.session.add(key_record)
        record = persist_issued_certificate(
            user=user,
            reviewer=None,
            csr_pem=generated.csr_pem,
            certificate_pem=certificate_pem,
            reviewed_at=now,
        )
        db.session.commit()
    except (PKIError, ValueError) as error:
        db.session.rollback()
        raise click.ClickException(str(error)) from error
    click.echo(f"Issued certificate serial: {record.serial_number}")
    click.echo(f"Certificate SHA-256 fingerprint: {record.fingerprint}")
    click.echo("The development private key was stored only as encrypted PKCS#8 data.")


@pki_cli.command("create-development-admin")
@click.option("--name", required=True, help="Administrator display name.")
@click.option("--email", required=True, help="Administrator email.")
def create_development_admin(name: str, email: str) -> None:
    """Create a disabled CA-admin identity for local CLI revocation records."""
    import secrets

    normalized_email = email.strip().casefold()
    if db.session.query(User).filter_by(email=normalized_email).one_or_none() is not None:
        raise click.ClickException("A user with that email already exists")
    administrator = User(
        full_name=name,
        email=normalized_email,
        role="ca_admin",
        status="disabled",
    )
    administrator.set_password(secrets.token_urlsafe(48))
    db.session.add(administrator)
    db.session.commit()
    click.echo(f"Created disabled development CA administrator ID: {administrator.id}")
    click.echo("No reusable login credential was created or displayed.")


@pki_cli.command("revoke")
@click.option("--serial", required=True, help="Decimal certificate serial number.")
@click.option("--admin-id", required=True, type=click.IntRange(min=1))
@click.option(
    "--reason",
    required=True,
    type=click.Choice(sorted(ALLOWED_REVOCATION_REASONS), case_sensitive=True),
)
def revoke_certificate(serial: str, admin_id: int, reason: str) -> None:
    """Revoke an issued certificate in the local database."""
    record = db.session.query(Certificate).filter_by(serial_number=serial).one_or_none()
    administrator = db.session.get(User, admin_id)
    if record is None:
        raise click.ClickException("Certificate serial number was not found")
    if administrator is None:
        raise click.ClickException("Administrator user was not found")
    try:
        revoke_persisted_certificate(certificate=record, administrator=administrator, reason=reason)
        db.session.commit()
    except PKIError as error:
        db.session.rollback()
        raise click.ClickException(str(error)) from error
    click.echo(f"Revoked certificate serial: {record.serial_number}")
    click.echo(f"Reason: {reason}")


@pki_cli.command("generate-crl")
def generate_crl() -> None:
    """Generate and publish the Issuing CA's current full CRL."""
    try:
        service = PKIService.from_config(current_app.config)
        now = datetime.now(UTC)
        crl_pem = service.generate_crl(
            revocation_entries(), this_update=now, next_update=now + timedelta(days=7)
        )
        service.write_crl(crl_pem)
        crl = x509.load_pem_x509_crl(crl_pem)
    except PKIError as error:
        raise click.ClickException(str(error)) from error
    click.echo(f"Generated CRL with {len(crl)} revoked certificate(s).")
    click.echo(f"CRL SHA-256 fingerprint: {crl.fingerprint(hashes.SHA256()).hex()}")


def register_cli(app) -> None:
    app.cli.add_command(pki_cli)
