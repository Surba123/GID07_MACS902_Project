"""Extension objects are constructed once and bound in the app factory."""

import sqlite3

from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from sqlalchemy import event
from sqlalchemy.engine import Engine


@event.listens_for(Engine, "connect")
def enable_sqlite_foreign_keys(connection, connection_record) -> None:
    """SQLite otherwise parses foreign keys without enforcing them."""
    if isinstance(connection, sqlite3.Connection):
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
login_manager.login_view = "auth.login"
csrf = CSRFProtect()
