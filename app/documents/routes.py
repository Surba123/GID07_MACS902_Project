"""Public verification plus authenticated owner-scoped Phase 4 document routes."""

from io import BytesIO

from flask import current_app, flash, redirect, render_template, request, send_file, url_for
from flask_login import current_user, login_required

from app.crypto.encryption import DocumentEncryptionError, DocumentEncryptionService
from app.documents import bp
from app.documents.service import DocumentSigningError, DocumentSigningService, validate_upload
from app.extensions import db
from app.models import AuditEvent, Certificate, EncryptedDocument, KeyRecord, SignatureRecord, User


def _service() -> DocumentSigningService:
    return DocumentSigningService.from_config(current_app.config)


@bp.get("/")
def index():
    signatures = []
    certificates = []
    encrypted_sent = []
    encrypted_received = []
    recipients = []
    if current_user.is_authenticated:
        signatures = (
            db.session.query(SignatureRecord)
            .filter_by(signer_id=current_user.id)
            .order_by(SignatureRecord.created_at.desc())
            .all()
        )
        certificates = (
            db.session.query(Certificate).filter_by(user_id=current_user.id, status="active").all()
        )
        encrypted_sent = (
            db.session.query(EncryptedDocument).filter_by(sender_id=current_user.id).all()
        )
        encrypted_received = (
            db.session.query(EncryptedDocument).filter_by(recipient_id=current_user.id).all()
        )
        recipients = (
            db.session.query(User)
            .join(KeyRecord)
            .filter(
                User.id != current_user.id,
                User.status == "active",
                KeyRecord.purpose == "key_agreement",
                KeyRecord.status == "active",
            )
            .all()
        )
    return render_template(
        "documents/index.html",
        certificates=certificates,
        signatures=signatures,
        encrypted_sent=encrypted_sent,
        encrypted_received=encrypted_received,
        recipients=recipients,
        max_bytes=current_app.config["MAX_CONTENT_LENGTH"],
    )


@bp.post("/sign")
@login_required
def sign():
    upload = request.files.get("document")
    certificate = (
        db.session.query(Certificate).filter_by(user_id=current_user.id, status="active").first()
    )
    if upload is None or certificate is None:
        flash("An uploaded document and your active signing certificate are required.", "error")
        return redirect(url_for("documents.index"))
    try:
        record = _service().sign_document(
            signer=current_user,
            certificate=certificate,
            data=upload.read(),
            filename=upload.filename,
            password=request.form.get("password", ""),
        )
        db.session.commit()
    except (DocumentSigningError, ValueError) as error:
        db.session.rollback()
        flash(str(error), "error")
        return redirect(url_for("documents.index"))
    flash(f"Document signed. Signature ID: {record.public_id}", "success")
    return redirect(url_for("documents.index"))


@bp.get("/signatures/<public_id>/package")
@login_required
def download_signature_package(public_id: str):
    record = db.session.query(SignatureRecord).filter_by(public_id=public_id).one_or_none()
    if record is None or record.signer_id != current_user.id:
        return ("Forbidden", 403)
    return send_file(
        BytesIO(record.package_data),
        mimetype="application/json",
        as_attachment=True,
        download_name=f"signature-{record.public_id}.json",
    )


@bp.post("/verify")
def verify():
    document = request.files.get("document")
    selected_id = request.form.get("signature_id", type=int)
    package_upload = request.files.get("package")
    if document is None:
        flash("Select the document to verify.", "error")
        return redirect(url_for("documents.index"))
    try:
        # The filename policy also protects verification uploads; verification never writes them.
        validate_upload(
            document.filename, document.read(), int(current_app.config["MAX_CONTENT_LENGTH"])
        )
        document.stream.seek(0)
        data = document.read()
        if package_upload and package_upload.filename:
            package = package_upload.read()
            target = "portable_package"
        else:
            record = db.session.get(SignatureRecord, selected_id)
            if record is None:
                raise DocumentSigningError("Select a stored signature record or upload a package")
            if not current_user.is_authenticated or record.signer_id != current_user.id:
                raise DocumentSigningError("Upload the portable package to verify this signature")
            package = record.package_data
            target = record.public_id
        result = _service().verify(data=data, package_data=package)
        db.session.add(
            AuditEvent(
                action="document_verified",
                target_type="signature",
                target_id=target,
                outcome="success" if result.overall_valid else "failure",
                safe_detail=",".join(result.reasons)[:1024] or "valid",
            )
        )
        db.session.commit()
    except (DocumentSigningError, ValueError) as error:
        db.session.rollback()
        flash(str(error), "error")
        return redirect(url_for("documents.index"))
    return render_template("documents/verification.html", result=result)


@bp.post("/encrypt")
@login_required
def encrypt():
    upload = request.files.get("document")
    recipient = db.session.get(User, request.form.get("recipient_id", type=int))
    if (
        upload is None
        or recipient is None
        or recipient.id == current_user.id
        or recipient.status != "active"
    ):
        flash("Select a document and another active recipient.", "error")
        return redirect(url_for("documents.index"))
    try:
        DocumentEncryptionService.from_config(current_app.config).encrypt(
            sender=current_user,
            recipient=recipient,
            data=upload.read(),
            filename=upload.filename,
        )
        db.session.commit()
        flash("Document encrypted for the selected recipient.", "success")
    except DocumentEncryptionError as error:
        db.session.rollback()
        db.session.add(
            AuditEvent(
                actor=current_user,
                action="document_encryption_failed",
                target_type="user",
                target_id=str(recipient.id),
                outcome="failure",
                safe_detail="validation_or_key_failure",
            )
        )
        db.session.commit()
        flash(str(error), "error")
    return redirect(url_for("documents.index"))


@bp.post("/encrypted/<public_id>/decrypt")
@login_required
def decrypt(public_id: str):
    record = db.session.query(EncryptedDocument).filter_by(public_id=public_id).one_or_none()
    if record is None or record.recipient_id != current_user.id:
        db.session.add(
            AuditEvent(
                actor=current_user,
                action="decrypt_access_denied",
                target_type="encrypted_document",
                target_id=public_id,
                outcome="denied",
            )
        )
        db.session.commit()
        return ("Forbidden", 403)
    try:
        result = DocumentEncryptionService.from_config(current_app.config).decrypt(
            record=record, recipient=current_user, password=request.form.get("password", "")
        )
        db.session.commit()
    except DocumentEncryptionError as error:
        db.session.rollback()
        db.session.add(
            AuditEvent(
                actor=current_user,
                action="document_decryption_failed",
                target_type="encrypted_document",
                target_id=record.public_id,
                outcome="failure",
                safe_detail="authentication_or_integrity_failure",
            )
        )
        db.session.commit()
        flash(str(error), "error")
        return redirect(url_for("documents.index"))
    return send_file(
        BytesIO(result.data),
        mimetype=result.media_type,
        as_attachment=True,
        download_name=result.filename,
    )
