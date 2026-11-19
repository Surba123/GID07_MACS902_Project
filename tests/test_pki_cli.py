from app.extensions import db
from app.models import Certificate, KeyRecord, RevocationRecord, User


def test_pki_init_cli_creates_encrypted_keys_without_printing_them(app, tmp_path):
    key_dir = tmp_path / "ca-keys"
    cert_dir = tmp_path / "ca-certificates"
    app.config.update(
        CA_KEY_DIR=key_dir,
        CA_CERT_DIR=cert_dir,
        PKI_CA_KEY_PASSWORD="cli-test-ca-password-long-enough",
    )
    result = app.test_cli_runner().invoke(args=["pki", "init"])
    assert result.exit_code == 0, result.output
    assert "fingerprint" in result.output
    assert "PRIVATE KEY" not in result.output
    for filename in ("root_ca_private_key.pem", "issuing_ca_private_key.pem"):
        content = (key_dir / filename).read_bytes()
        assert b"BEGIN ENCRYPTED PRIVATE KEY" in content
        assert b"BEGIN PRIVATE KEY" not in content


def test_development_issue_revoke_and_crl_cli_flow_avoids_key_output(app, tmp_path):
    app.config.update(
        CA_KEY_DIR=tmp_path / "ca-keys",
        CA_CERT_DIR=tmp_path / "ca-certificates",
        PKI_CA_KEY_PASSWORD="cli-test-ca-password-long-enough",
        PKI_DEVELOPMENT_USER_KEY_PASSWORD="cli-test-user-password-long-enough",
    )
    runner = app.test_cli_runner()
    assert runner.invoke(args=["pki", "init"]).exit_code == 0

    issue = runner.invoke(
        args=[
            "pki",
            "issue-development-certificate",
            "--name",
            "Alice Example",
            "--email",
            "alice@example.test",
            "--valid-days",
            "30",
        ]
    )
    assert issue.exit_code == 0, issue.output
    assert "PRIVATE KEY" not in issue.output
    key_record = db.session.query(KeyRecord).one()
    certificate = db.session.query(Certificate).one()
    assert key_record.encrypted_private_key_data.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY")
    assert b"BEGIN PRIVATE KEY" not in key_record.encrypted_private_key_data

    create_admin = runner.invoke(
        args=[
            "pki",
            "create-development-admin",
            "--name",
            "CA Administrator",
            "--email",
            "admin@example.test",
        ]
    )
    assert create_admin.exit_code == 0, create_admin.output
    assert "password" not in create_admin.output.casefold()
    administrator = db.session.query(User).filter_by(role="ca_admin").one()

    revoke = runner.invoke(
        args=[
            "pki",
            "revoke",
            "--serial",
            certificate.serial_number,
            "--admin-id",
            str(administrator.id),
            "--reason",
            "key_compromise",
        ]
    )
    assert revoke.exit_code == 0, revoke.output
    assert db.session.query(RevocationRecord).one().reason == "key_compromise"

    generate_crl = runner.invoke(args=["pki", "generate-crl"])
    assert generate_crl.exit_code == 0, generate_crl.output
    assert "PRIVATE KEY" not in generate_crl.output
    assert (tmp_path / "ca-certificates" / "issuing_ca.crl.pem").exists()
