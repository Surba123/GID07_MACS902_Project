"""Constrain certificate revocation reasons.

Revision ID: 9f2a3c4d5e6f
Revises: 1886200ff033
Create Date: 2026-10-20
"""

from alembic import op

revision = "9f2a3c4d5e6f"
down_revision = "1886200ff033"
branch_labels = None
depends_on = None

_REASON_CHECK = (
    "reason IN ('unspecified', 'key_compromise', 'ca_compromise', "
    "'affiliation_changed', 'superseded', 'cessation_of_operation', "
    "'certificate_hold', 'privilege_withdrawn', 'aa_compromise')"
)


def upgrade():
    with op.batch_alter_table("revocation_records", schema=None) as batch_op:
        batch_op.create_check_constraint("ck_revocations_reason", _REASON_CHECK)


def downgrade():
    with op.batch_alter_table("revocation_records", schema=None) as batch_op:
        batch_op.drop_constraint("ck_revocations_reason", type_="check")
