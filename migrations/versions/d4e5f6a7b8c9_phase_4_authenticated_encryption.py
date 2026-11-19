"""Phase 4 authenticated workflows and encrypted document metadata.

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
"""

import sqlalchemy as sa
from alembic import op

revision = "d4e5f6a7b8c9"
down_revision = "c3d4e5f6a7b8"
branch_labels = None
depends_on = None


def upgrade():
    # SQLite supports adding a nullable REFERENCES column without rebuilding this parent table.
    # Avoiding batch recreation preserves existing Certificate -> CertificateRequest foreign keys.
    op.execute(
        "ALTER TABLE certificate_requests ADD COLUMN key_record_id "
        "INTEGER REFERENCES key_records(id)"
    )
    op.create_index(
        "ix_certificate_requests_key_record_id",
        "certificate_requests",
        ["key_record_id"],
        unique=True,
    )
    with op.batch_alter_table("encrypted_documents") as batch_op:
        batch_op.add_column(sa.Column("public_id", sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column("original_filename", sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column("media_type", sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column("byte_length", sa.Integer(), nullable=True))
    op.execute(
        "UPDATE encrypted_documents SET public_id=lower(hex(randomblob(16))), "
        "original_filename='legacy.bin', media_type='application/octet-stream', "
        "byte_length=0 WHERE public_id IS NULL"
    )
    with op.batch_alter_table("encrypted_documents") as batch_op:
        for column in ("public_id", "original_filename", "media_type", "byte_length"):
            batch_op.alter_column(column, nullable=False)
        batch_op.create_index("ix_encrypted_documents_public_id", ["public_id"], unique=True)


def downgrade():
    with op.batch_alter_table("encrypted_documents") as batch_op:
        batch_op.drop_index("ix_encrypted_documents_public_id")
        batch_op.drop_column("byte_length")
        batch_op.drop_column("media_type")
        batch_op.drop_column("original_filename")
        batch_op.drop_column("public_id")
    op.drop_index("ix_certificate_requests_key_record_id", table_name="certificate_requests")
    op.execute("ALTER TABLE certificate_requests DROP COLUMN key_record_id")
