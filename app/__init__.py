"""Application factory and local runtime setup."""

from pathlib import Path

from dotenv import load_dotenv
from flask import Flask

from app.config import build_config
from app.extensions import csrf, db, login_manager, migrate


def _create_private_directories(app: Flask) -> None:
    """Create private storage before any route can use it."""
    public_root = Path(app.static_folder).resolve()
    for key in (
        "STORAGE_ROOT",
        "UPLOAD_DIR",
        "ENCRYPTED_DIR",
        "DECRYPTED_TMP_DIR",
        "CA_KEY_DIR",
        "USER_KEY_DIR",
        "CA_CERT_DIR",
    ):
        directory = Path(app.config[key]).resolve()
        if directory == public_root or public_root in directory.parents:
            raise ValueError(f"{key} must be outside Flask's public static directory")
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)


def create_app(config_name: str | None = None, *, test_config: dict | None = None) -> Flask:
    """Build an importable Flask app without starting a server or creating tables."""
    project_root = Path(__file__).resolve().parent.parent
    load_dotenv(project_root / ".env", override=False)
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(build_config(config_name, Path(app.instance_path)))
    if test_config:
        app.config.update(test_config)
        if "STORAGE_ROOT" in test_config:
            storage = Path(test_config["STORAGE_ROOT"])
            for key, child in (
                ("UPLOAD_DIR", "uploads"),
                ("ENCRYPTED_DIR", "encrypted"),
                ("DECRYPTED_TMP_DIR", "decrypted_tmp"),
                ("CA_KEY_DIR", "ca_private_keys"),
                ("USER_KEY_DIR", "user_private_keys"),
                ("CA_CERT_DIR", "ca_certificates"),
            ):
                if key not in test_config:
                    app.config[key] = storage / child
    _create_private_directories(app)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)

    from app import models  # noqa: F401 - register model metadata before migrations
    from app.admin import bp as admin_bp
    from app.auth import bp as auth_bp
    from app.auth.cli import register_cli as register_user_cli
    from app.documents import bp as documents_bp
    from app.errors import register_error_handlers
    from app.main import bp as main_bp
    from app.pki.cli import register_cli

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(documents_bp)
    app.register_blueprint(admin_bp)
    register_error_handlers(app)
    register_cli(app)
    register_user_cli(app)
    return app
