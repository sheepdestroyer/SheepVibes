"""add_user_table

Revision ID: e1c0929eb6fc
Revises: 996291c6a151
Create Date: 2025-06-14 20:01:11.400652

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e1c0929eb6fc'
down_revision = '996291c6a151'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), nullable=False, primary_key=True, autoincrement=True),
        sa.Column('username', sa.String(), nullable=False, unique=True),
        sa.Column('password_hash', sa.String(), nullable=False)
    )


def downgrade():
    op.drop_table('users')
