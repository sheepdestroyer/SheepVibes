"""canonicalize existing feed names

Revision ID: a1b2c3d4e5f6
Revises: 8e59ae7a1c5b
Create Date: 2026-08-14 10:52:00.000000

"""
from alembic import op
import sqlalchemy as sa
from backend.feed_name_utils import derive_canonical_feed_name


# revision identifiers, used by Alembic.
revision = 'a1b2c3d4e5f6'
down_revision = '8e59ae7a1c5b'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    feeds_table = sa.table(
        "feeds",
        sa.column("id", sa.Integer),
        sa.column("name", sa.String),
        sa.column("url", sa.String),
        sa.column("site_link", sa.String),
    )

    results = bind.execute(
        sa.select(
            feeds_table.c.id,
            feeds_table.c.name,
            feeds_table.c.url,
            feeds_table.c.site_link,
        )
    ).fetchall()

    for feed_id, current_name, url, site_link in results:
        new_name = derive_canonical_feed_name(
            current_name, site_url=site_link, feed_url=url
        )
        if new_name and new_name != current_name:
            bind.execute(
                feeds_table.update()
                .where(feeds_table.c.id == feed_id)
                .values(name=new_name)
            )


def downgrade():
    pass
