from flask import jsonify, render_template

from app.main import bp


@bp.get("/")
def index():
    return render_template("main/index.html")


@bp.get("/health")
def health():
    return jsonify(status="ok", service="macs902-pki-document-system")
