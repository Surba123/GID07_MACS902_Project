from flask import Flask

from app import create_app
from app.extensions import csrf, db, login_manager, migrate


def test_factory_registers_extensions_and_blueprints(app):
    assert isinstance(app, Flask)
    assert app.testing
    assert {"main", "auth", "documents", "admin"} <= set(app.blueprints)
    assert app.extensions["sqlalchemy"] is db
    assert migrate.db is db
    assert login_manager.login_view == "auth.login"
    assert app.extensions["csrf"] is csrf


def test_factory_creates_private_runtime_directories(app):
    for key in (
        "STORAGE_ROOT",
        "UPLOAD_DIR",
        "ENCRYPTED_DIR",
        "DECRYPTED_TMP_DIR",
        "CA_KEY_DIR",
        "USER_KEY_DIR",
        "CA_CERT_DIR",
    ):
        assert app.config[key].is_dir()
        assert not app.config[key].is_relative_to(app.static_folder)


def test_factory_rejects_public_storage():
    # A normal app's real static path must never be an upload destination.
    probe = create_app("testing")
    from pytest import raises

    with raises(ValueError, match="outside Flask"):
        create_app("testing", test_config={"UPLOAD_DIR": probe.static_folder})
