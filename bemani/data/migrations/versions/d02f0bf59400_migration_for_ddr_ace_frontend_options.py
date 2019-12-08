"""Migration for DDR Ace frontend options.

Revision ID: d02f0bf59400
Revises: 693fadb665ba
Create Date: 2018-02-18 13:01:01.497029

"""
import json
from alembic import op
from sqlalchemy.sql import text

# revision identifiers, used by Alembic.
revision = 'd02f0bf59400'
down_revision = '693fadb665ba'
branch_labels = None
depends_on = None


GAME_OPTION_ARROW_SKIN_OFFSET = 11
GAME_OPTION_FILTER_OFFSET = 12
GAME_OPTION_GUIDELINE_OFFSET = 13
GAME_OPTION_COMBO_POSITION_OFFSET = 15
GAME_OPTION_FAST_SLOW_OFFSET = 16


def upgrade():
    conn = op.get_bind()

    sql = "SELECT refid, data FROM profile WHERE refid IN (SELECT refid FROM refid WHERE game = 'ddr' AND version = 16)"
    results = conn.execute(text(sql), {})
    for result in results:
        refid = result['refid']
        profile = json.loads(result['data'])

        if (
            'usergamedata' in profile and
            'OPTION' in profile['usergamedata'] and
            'strdata' in profile['usergamedata']['OPTION']
        ):
            option = bytes(profile['usergamedata']['OPTION']['strdata'][1:]).split(b',')
            if 'combo' not in profile:
                profile['combo'] = int(option[GAME_OPTION_COMBO_POSITION_OFFSET].decode('ascii'), 16)
            if 'early_late' not in profile:
                profile['early_late'] = int(option[GAME_OPTION_FAST_SLOW_OFFSET].decode('ascii'), 16)
            if 'arrowskin' not in profile:
                profile['arrowskin'] = int(option[GAME_OPTION_ARROW_SKIN_OFFSET].decode('ascii'), 16)
            if 'guidelines' not in profile:
                profile['guidelines'] = int(option[GAME_OPTION_GUIDELINE_OFFSET].decode('ascii'), 16)
            if 'filter' not in profile:
                profile['filter'] = int(option[GAME_OPTION_FILTER_OFFSET].decode('ascii'), 16)

        sql = "UPDATE profile SET data = :data WHERE refid = :refid"
        conn.execute(
            text(sql),
            {
                'refid': refid,
                'data': json.dumps(profile),
            },
        )


def downgrade():
    pass
