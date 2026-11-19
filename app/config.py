"""Environment-based configuration; no runtime secret is checked into source."""

import os
from pathlib import Path


class BaseConfig:
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = True
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600


class DevelopmentConfig(BaseConfig):
    # Keep browser error responses on the controlled 500 page during demos.
    DEBUG = False
    SESSION_COOKIE_SECURE = False  # local HTTP only


class TestingConfig(BaseConfig):
    TESTING = True
    SECRET_KEY = "phase-1-test-key-only"
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite://"  # overridden by isolated file in test fixture
    SESSION_COOKIE_SECURE = False


def build_config(name: str | None, instance_path: Path) -> dict:
    """Resolve a named configuration and private local paths."""
    selected = (name or os.getenv("FLASK_CONFIG", "development")).lower()
    classes = {"development": DevelopmentConfig, "testing": TestingConfig}
    if selected not in classes:
        raise ValueError(f"Unknown configuration: {selected}")
    config_class = classes[selected]
    config = {key: getattr(config_class, key) for key in dir(config_class) if key.isupper()}

    config["PKI_CA_KEY_PASSWORD"] = config.get("PKI_CA_KEY_PASSWORD") or os.getenv(
        "PKI_CA_KEY_PASSWORD"
    )
    config["PKI_DEVELOPMENT_USER_KEY_PASSWORD"] = config.get(
        "PKI_DEVELOPMENT_USER_KEY_PASSWORD"
    ) or os.getenv("PKI_DEVELOPMENT_USER_KEY_PASSWORD")
    config["PKI_ROOT_CA_NAME"] = os.getenv("PKI_ROOT_CA_NAME", "MACS902 Classroom Root CA")
    config["PKI_ISSUING_CA_NAME"] = os.getenv("PKI_ISSUING_CA_NAME", "MACS902 Classroom Issuing CA")

    if selected != "testing":
        secret = os.getenv("SECRET_KEY")
        if not secret or secret == "replace-with-a-new-random-local-value":
            raise RuntimeError(
                "SECRET_KEY is required. Copy .env.example to .env and generate a random value."
            )
        config["SECRET_KEY"] = secret
        config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL") or (
            f"sqlite:///{(instance_path / 'macs902.db').as_posix()}"
        )

    storage = Path(os.getenv("STORAGE_ROOT") or instance_path / "storage").resolve()
    if selected == "testing":
        storage = (instance_path / "test-storage").resolve()
    config.update(
        STORAGE_ROOT=storage,
        UPLOAD_DIR=storage / "uploads",
        ENCRYPTED_DIR=storage / "encrypted",
        DECRYPTED_TMP_DIR=storage / "decrypted_tmp",
        CA_KEY_DIR=storage / "ca_private_keys",
        USER_KEY_DIR=storage / "user_private_keys",
        CA_CERT_DIR=storage / "ca_certificates",
    )
    return config
