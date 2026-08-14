"""add user model and tab user_id foreign key

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-08-14 11:23:00.000000

"""
import datetime
from datetime import timezone
from alembic import op
import sqlalchemy as sa
from werkzeug.security import generate_password_hash


# revision identifiers, used by Alembic.
revision = 'b2c3d4e5f6a7'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None


def upgrade():
    # 1. Create users table
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(length=80), nullable=False),
        sa.Column('email', sa.String(length=120), nullable=True),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('role', sa.String(length=20), nullable=False, server_default='user'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('last_login_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email')
    )
    op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)

    # 2. Add user_id to tabs table
    with op.batch_alter_table('tabs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('user_id', sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            'fk_tabs_user_id_users', 'users', ['user_id'], ['id'], ondelete='CASCADE'
        )
        batch_op.create_index('ix_tabs_user_id', ['user_id'], unique=False)

    # 3. Seed default admin user and associate existing tabs if any
    bind = op.get_bind()
    users_table = sa.table(
        'users',
        sa.column('id', sa.Integer),
        sa.column('username', sa.String),
        sa.column('email', sa.String),
        sa.column('password_hash', sa.String),
        sa.column('role', sa.String),
        sa.column('is_active', sa.Boolean),
        sa.column('created_at', sa.DateTime),
        sa.column('last_login_at', sa.DateTime),
    )
    tabs_table = sa.table(
        'tabs',
        sa.column('id', sa.Integer),
        sa.column('user_id', sa.Integer),
    )

    existing_tabs = bind.execute(sa.select(tabs_table.c.id)).fetchall()
    if existing_tabs:
        # Create default admin account
        now = datetime.datetime.now(timezone.utc)
        pwd_hash = generate_password_hash("admin")
        result = bind.execute(
            users_table.insert().values(
                username='admin',
                email=None,
                password_hash=pwd_hash,
                role='admin',
                is_active=True,
                created_at=now,
                last_login_at=None,
            )
        )
        admin_id = result.inserted_primary_key[0] if result.inserted_primary_key else 1

        # Associate all existing tabs with default admin
        bind.execute(
            tabs_table.update().values(user_id=admin_id)
        )


def downgrade():
    with op.batch_alter_table('tabs', schema=None) as batch_op:
        batch_op.drop_index('ix_tabs_user_id')
        batch_op.drop_constraint('fk_tabs_user_id_users', type_='foreignkey')
        batch_op.drop_column('user_id')

    op.drop_index(op.f('ix_users_username'), table_name='users')
    op.drop_table('users')
