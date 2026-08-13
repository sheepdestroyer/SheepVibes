"""add comments_url to feed_items

Revision ID: 8e59ae7a1c5b
Revises: 14d8ad95ac2e
Create Date: 2026-08-14 01:26:12.766553

"""
from alembic import op
import sqlalchemy as sa
from backend.migration_helpers import safe_drop_constraint, constraint_exists


# revision identifiers, used by Alembic.
revision = '8e59ae7a1c5b'
down_revision = '14d8ad95ac2e'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("feed_items", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("comments_url", sa.String(), nullable=True)
        )


def downgrade():
    with op.batch_alter_table("feed_items", schema=None) as batch_op:
        batch_op.drop_column("comments_url")
