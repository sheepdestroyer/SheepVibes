"""Add site_link to Feed model

Revision ID: 44ddebc82c69
Revises: 996291c6a151
Create Date: 2025-06-22 21:15:41.711211

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '44ddebc82c69'
down_revision = '996291c6a151'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('feed_items', schema=None) as batch_op:
        batch_op.create_unique_constraint('uq_feed_item_feed_id_guid', ['feed_id', 'guid'])

    with op.batch_alter_table('feeds', schema=None) as batch_op:
        batch_op.add_column(sa.Column('site_link', sa.String(length=500), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('feeds', schema=None) as batch_op:
        batch_op.drop_column('site_link')

    with op.batch_alter_table('feed_items', schema=None) as batch_op:
        batch_op.drop_constraint('uq_feed_item_feed_id_guid', type_='unique')

    # ### end Alembic commands ###
