from pathlib import Path

import pytest

from app import create_app
from app.config import build_config


def test_development_requires_external_secret(monkeypatch, tmp_path):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError, match="SECRET_KEY is required"):
        build_config("development", tmp_path)


def test_development_and_testing_are_separate(monkeypatch, tmp_path):
    monkeypatch.setenv("SECRET_KEY", "local-development-test-value")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'development.db').as_posix()}")
    development = build_config("development", tmp_path)
    testing = build_config("testing", tmp_path)
    assert development["SECRET_KEY"] != testing["SECRET_KEY"]
    assert development["SQLALCHEMY_DATABASE_URI"] != testing["SQLALCHEMY_DATABASE_URI"]
    assert development["WTF_CSRF_ENABLED"]
    assert development["DEBUG"] is False
    assert not testing["WTF_CSRF_ENABLED"]
    assert development["SESSION_COOKIE_SECURE"] is False


def test_testing_never_creates_development_database(monkeypatch, tmp_path):
    dev_db = tmp_path / "development.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{dev_db.as_posix()}")
    app = create_app(
        "testing",
        test_config={
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{(tmp_path / 'isolated.db').as_posix()}"
        },
    )
    from app.extensions import db

    with app.app_context():
        db.create_all()
        db.engine.dispose()
    assert Path(tmp_path / "isolated.db").exists()
    assert not dev_db.exists()
