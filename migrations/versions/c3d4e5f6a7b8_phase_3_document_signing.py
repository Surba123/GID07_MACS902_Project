"""Phase 3 document signing package metadata.

Revision ID: c3d4e5f6a7b8
Revises: 9f2a3c4d5e6f
Create Date: 2026-10-20
"""

import sqlalchemy as sa
from alembic import op

revision = "c3d4e5f6a7b8"
down_revision = "9f2a3c4d5e6f"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("documents") as batch_op:
        batch_op.add_column(
            sa.Column(
                "media_type", sa.String(length=100), nullable=False, server_default="text/plain"
            )
        )
        batch_op.add_column(
            sa.Column("byte_length", sa.Integer(), nullable=False, server_default="0")
        )
    with op.batch_alter_table("signature_records") as batch_op:
        batch_op.add_column(sa.Column("public_id", sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column("package_data", sa.LargeBinary(), nullable=True))
    # Existing placeholder records need non-sensitive markers before constraints are added.
    op.execute(
        "UPDATE signature_records SET public_id = lower(hex(randomblob(16))) "
        "WHERE public_id IS NULL"
    )
    op.execute("UPDATE signature_records SET package_data = X'' WHERE package_data IS NULL")
    with op.batch_alter_table("signature_records") as batch_op:
        batch_op.alter_column("public_id", nullable=False)
        batch_op.alter_column("package_data", nullable=False)
        batch_op.create_unique_constraint("uq_signature_records_public_id", ["public_id"])
        batch_op.create_index("ix_signature_records_public_id", ["public_id"], unique=True)


def downgrade():
    with op.batch_alter_table("signature_records") as batch_op:
        batch_op.drop_index("ix_signature_records_public_id")
        batch_op.drop_constraint("uq_signature_records_public_id", type_="unique")
        batch_op.drop_column("package_data")
        batch_op.drop_column("public_id")
    with op.batch_alter_table("documents") as batch_op:
        batch_op.drop_column("byte_length")
        batch_op.drop_column("media_type")
