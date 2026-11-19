"""Local authenticated-user lifecycle."""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from flask import current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy.exc import IntegrityError

from app.auth import bp
from app.auth.forms import LoginForm, RegistrationForm
from app.crypto.key_protection import protect_private_key
from app.extensions import db
from app.models import AuditEvent, KeyRecord, User
from app.pki.service import PKIService
from app.pki.workflow import CertificateWorkflowError, create_signing_request


@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("auth.dashboard"))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(full_name=form.full_name.data.strip(), email=form.email.data)
        user.set_password(form.password.data)
        private_key = x25519.X25519PrivateKey.generate()
        raw_private = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        protected = protect_private_key(raw_private, form.password.data, purpose="key_agreement")
        key_record = KeyRecord(
            user=user,
            purpose="key_agreement",
            algorithm="X25519",
            public_key_data=private_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
            encrypted_private_key_data=protected.ciphertext,
            private_key_kdf=protected.kdf,
            private_key_salt=protected.salt,
            private_key_nonce=protected.nonce,
            status="active",
        )
        db.session.add_all(
            [
                user,
                key_record,
                AuditEvent(
                    actor=user,
                    action="registration",
                    target_type="user",
                    outcome="success",
                ),
            ]
        )
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("Registration could not be completed.", "error")
        else:
            login_user(user)
            return redirect(url_for("auth.dashboard"))
    return render_template("auth/register.html", form=form)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("auth.dashboard"))
    form = LoginForm()
    if form.validate_on_submit():
        user = (
            db.session.query(User).filter_by(email=form.email.data.strip().casefold()).one_or_none()
        )
        if user is not None and user.is_active and user.verify_password(form.password.data):
            login_user(user)
            db.session.add(
                AuditEvent(actor=user, action="login", target_type="user", outcome="success")
            )
            db.session.commit()
            return redirect(url_for("auth.dashboard"))
        db.session.add(AuditEvent(action="login", target_type="user", outcome="failure"))
        db.session.commit()
        flash("Invalid email or password.", "error")
    return render_template("auth/login.html", form=form)


@bp.post("/logout")
@login_required
def logout():
    db.session.add(
        AuditEvent(actor=current_user, action="logout", target_type="user", outcome="success")
    )
    db.session.commit()
    logout_user()
    return redirect(url_for("main.index"))


@bp.get("/dashboard")
@login_required
def dashboard():
    events = (
        db.session.query(AuditEvent)
        .filter_by(actor_id=current_user.id)
        .order_by(AuditEvent.created_at.desc())
        .limit(25)
        .all()
    )
    return render_template("auth/dashboard.html", events=events)


@bp.post("/request-signing-certificate")
@login_required
def request_certificate():
    try:
        create_signing_request(
            user=current_user,
            password=request.form.get("password", ""),
            pki=PKIService.from_config(current_app.config),
        )
        db.session.commit()
        flash("Signing-certificate request submitted for administrator review.", "success")
    except CertificateWorkflowError as error:
        db.session.rollback()
        flash(str(error), "error")
    return redirect(url_for("auth.dashboard"))
