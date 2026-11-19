from pathlib import Path

import pytest

from app import create_app
from app.extensions import db


@pytest.fixture
def app(tmp_path: Path):
    storage = tmp_path / "private-storage"
    application = create_app(
        "testing",
        test_config={
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{(tmp_path / 'test.db').as_posix()}",
            "STORAGE_ROOT": storage,
            "UPLOAD_DIR": storage / "uploads",
            "ENCRYPTED_DIR": storage / "encrypted",
            "DECRYPTED_TMP_DIR": storage / "decrypted_tmp",
            "CA_KEY_DIR": storage / "ca_private_keys",
            "USER_KEY_DIR": storage / "user_private_keys",
        },
    )
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()
        db.engine.dispose()


@pytest.fixture
def client(app):
    return app.test_client()
