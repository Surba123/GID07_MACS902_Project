"""Administrator-only certificate lifecycle routes."""

from datetime import UTC, datetime, timedelta

from flask import current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user

from app.admin import bp
from app.auth.access import admin_required
from app.extensions import db
from app.models import AuditEvent, Certificate, CertificateRequest
from app.pki.errors import PKIError
from app.pki.lifecycle import revocation_entries, revoke_persisted_certificate
from app.pki.service import PKIService
from app.pki.workflow import (
    CertificateWorkflowError,
    approve_request,
    reject_request,
)


@bp.get("/")
@admin_required
def index():
    return render_template(
        "admin/index.html",
        requests=db.session.query(CertificateRequest)
        .order_by(CertificateRequest.submitted_at.desc())
        .all(),
        certificates=db.session.query(Certificate).order_by(Certificate.created_at.desc()).all(),
    )


def _refresh_crl() -> None:
    """Publish a new, signed full CRL using the persisted revocation records."""
    service = PKIService.from_config(current_app.config)
    now = datetime.now(UTC)
    service.write_crl(
        service.generate_crl(
            revocation_entries(),
            this_update=now,
            next_update=now + timedelta(days=7),
        )
    )


@bp.post("/requests/<int:request_id>/approve")
@admin_required
def approve(request_id: int):
    certificate_request = db.session.get(CertificateRequest, request_id)
    if certificate_request is None:
        return ("Not found", 404)
    try:
        service = PKIService.from_config(current_app.config)
        approve_request(
            request=certificate_request,
            administrator=current_user,
            pki=service,
        )
        # An issued certificate must not leave the application relying on an
        # expired CRL.  The CRL remains fail-closed when it is unavailable or
        # stale; this CA-admin action publishes a fresh signed full CRL.
        _refresh_crl()
        db.session.commit()
        flash("Certificate issued and CRL refreshed.", "success")
    except (CertificateWorkflowError, PKIError) as error:
        db.session.rollback()
        flash(str(error), "error")
    return redirect(url_for("admin.index"))


@bp.post("/crl/refresh")
@admin_required
def refresh_crl():
    """Let a CA administrator renew the short-lived signed CRL explicitly."""
    try:
        _refresh_crl()
        db.session.add(
            AuditEvent(
                actor=current_user,
                action="crl_refreshed",
                target_type="certificate_revocation_list",
                outcome="success",
            )
        )
        db.session.commit()
        flash("Certificate revocation list refreshed.", "success")
    except PKIError as error:
        db.session.rollback()
        flash(str(error), "error")
    return redirect(url_for("admin.index"))


@bp.post("/requests/<int:request_id>/reject")
@admin_required
def reject(request_id: int):
    certificate_request = db.session.get(CertificateRequest, request_id)
    if certificate_request is None:
        return ("Not found", 404)
    try:
        reject_request(
            request=certificate_request,
            administrator=current_user,
            reason=request.form.get("reason", ""),
        )
        db.session.commit()
        flash("Certificate request rejected.", "success")
    except CertificateWorkflowError as error:
        db.session.rollback()
        flash(str(error), "error")
    return redirect(url_for("admin.index"))


@bp.post("/certificates/<int:certificate_id>/revoke")
@admin_required
def revoke(certificate_id: int):
    certificate = db.session.get(Certificate, certificate_id)
    if certificate is None:
        return ("Not found", 404)
    try:
        revoke_persisted_certificate(
            certificate=certificate,
            administrator=current_user,
            reason=request.form.get("reason", "unspecified"),
        )
        _refresh_crl()
        db.session.add(
            AuditEvent(
                actor=current_user,
                action="certificate_revoked",
                target_type="certificate",
                target_id=str(certificate.id),
                outcome="success",
            )
        )
        db.session.commit()
        flash("Certificate revoked and CRL refreshed.", "success")
    except PKIError as error:
        db.session.rollback()
        flash(str(error), "error")
    return redirect(url_for("admin.index"))
