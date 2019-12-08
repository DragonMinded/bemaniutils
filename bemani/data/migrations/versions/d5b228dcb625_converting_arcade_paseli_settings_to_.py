"""Converting arcade paseli settings to dict like other tables.

Revision ID: d5b228dcb625
Revises: d7602d586661
Create Date: 2017-02-19 11:32:27.077094

"""
import json
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql
from sqlalchemy.sql import text

# revision identifiers, used by Alembic.
revision = 'd5b228dcb625'
down_revision = 'd7602d586661'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()

    # Add new column
    op.add_column('arcade', sa.Column('data', sa.JSON(), nullable=True))

    # Migrate current settings
    sql = 'SELECT id, paseli_enabled, paseli_infinite FROM arcade'
    results = conn.execute(text(sql), {})
    for result in results:
        sql = 'UPDATE arcade SET data = :data WHERE id = :id'
        conn.execute(text(sql), {
            'data': json.dumps({'paseli_enabled': result['paseli_enabled'] == 1, 'paseli_infinite': result['paseli_infinite'] == 1}),
            'id': result['id'],
        })

    # Drop old columns
    op.drop_column('arcade', 'paseli_enabled')
    op.drop_column('arcade', 'paseli_infinite')


def downgrade():
    op.add_column('arcade', sa.Column('paseli_infinite', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True))
    op.add_column('arcade', sa.Column('paseli_enabled', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True))
    op.drop_column('arcade', 'data')
