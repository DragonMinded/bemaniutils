"""Migration for DDR Ace common options.

Revision ID: 693fadb665ba
Revises: ad911b666f22
Create Date: 2018-02-18 12:10:29.357996

"""
import json
from alembic import op
from sqlalchemy.sql import text

# revision identifiers, used by Alembic.
revision = '693fadb665ba'
down_revision = 'ad911b666f22'
branch_labels = None
depends_on = None


GAME_COMMON_AREA_OFFSET = 1
GAME_COMMON_WEIGHT_DISPLAY_OFFSET = 3
GAME_COMMON_CHARACTER_OFFSET = 4
GAME_COMMON_WEIGHT_OFFSET = 17
GAME_COMMON_NAME_OFFSET = 25


def upgrade():
    conn = op.get_bind()

    sql = "SELECT refid, data FROM profile WHERE refid IN (SELECT refid FROM refid WHERE game = 'ddr' AND version = 16)"
    results = conn.execute(text(sql), {})
    for result in results:
        refid = result['refid']
        profile = json.loads(result['data'])

        if (
            'usergamedata' in profile and
            'COMMON' in profile['usergamedata'] and
            'strdata' in profile['usergamedata']['COMMON']
        ):
            common = bytes(profile['usergamedata']['COMMON']['strdata'][1:]).split(b',')
            if 'name' not in profile:
                profile['name'] = common[GAME_COMMON_NAME_OFFSET].decode('ascii')
            if 'area' not in profile:
                profile['area'] = int(common[GAME_COMMON_AREA_OFFSET].decode('ascii'), 16)
            if 'workout_mode' not in profile:
                profile['workout_mode'] = int(common[GAME_COMMON_WEIGHT_DISPLAY_OFFSET].decode('ascii'), 16) != 0
            if 'weight' not in profile:
                profile['weight'] = int(float(common[GAME_COMMON_WEIGHT_OFFSET].decode('ascii')) * 10)
            if 'character' not in profile:
                profile['character'] = int(common[GAME_COMMON_CHARACTER_OFFSET].decode('ascii'), 16)

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
