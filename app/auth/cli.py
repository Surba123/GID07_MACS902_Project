"""Trusted-terminal identity bootstrap commands."""

import click
from flask.cli import with_appcontext

from app.extensions import db
from app.models import User


@click.group("users")
def users_cli():
    """Manage local bootstrap identities."""


@users_cli.command("bootstrap-admin")
@click.option("--name", required=True)
@click.option("--email", required=True)
@click.password_option(confirmation_prompt=True)
@with_appcontext
def bootstrap_admin(name: str, email: str, password: str):
    if len(password) < 12:
        raise click.ClickException("The administrator password must contain at least 12 characters")
    if db.session.query(User).filter_by(email=email.strip().casefold()).first():
        raise click.ClickException("An account with that email already exists")
    user = User(full_name=name, email=email, role="ca_admin")
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    click.echo(f"Created local CA administrator ID: {user.id}")


def register_cli(app):
    app.cli.add_command(users_cli)
