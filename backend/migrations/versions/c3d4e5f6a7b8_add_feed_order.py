"""add order column to feeds

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-09-06 22:45:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c3d4e5f6a7b8'
down_revision = 'b2c3d4e5f6a7'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('feeds', schema=None) as batch_op:
        batch_op.add_column(sa.Column('order', sa.Integer(), nullable=False, server_default='0'))


def downgrade():
    with op.batch_alter_table('feeds', schema=None) as batch_op:
        batch_op.drop_column('order')
