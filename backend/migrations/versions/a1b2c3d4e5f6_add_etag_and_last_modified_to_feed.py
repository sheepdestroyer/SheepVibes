"""Add etag and last_modified to Feed

Revision ID: a1b2c3d4e5f6
Revises: 14d8ad95ac2e
Create Date: 2026-03-01 12:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "a1b2c3d4e5f6"
down_revision = "14d8ad95ac2e"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("feeds", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("etag", sa.String(length=255), nullable=True))
        batch_op.add_column(
            sa.Column("last_modified", sa.String(length=255), nullable=True))


def downgrade():
    with op.batch_alter_table("feeds", schema=None) as batch_op:
        batch_op.drop_column("last_modified")
        batch_op.drop_column("etag")
