"""init db

Revision ID: 3433293952c5
Revises: 
Create Date: 2022-08-18 17:25:49.789018

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '3433293952c5'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('achievement',
    sa.Column('refid', sa.String(length=16), nullable=False),
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('type', sa.String(length=64), nullable=False),
    sa.Column('data', sa.JSON(), nullable=False),
    sa.UniqueConstraint('refid', 'id', 'type', name='refid_id_type')
    )
    op.create_table('arcade',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('description', sa.String(length=255), nullable=False),
    sa.Column('pin', sa.String(length=8), nullable=False),
    sa.Column('pref', sa.Integer(), nullable=False),
    sa.Column('data', sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('arcade_owner',
    sa.Column('userid', mysql.BIGINT(unsigned=True), nullable=False),
    sa.Column('arcadeid', sa.Integer(), nullable=False),
    sa.UniqueConstraint('userid', 'arcadeid', name='arcade_userid_arcadeid')
    )
    op.create_table('arcade_settings',
    sa.Column('arcadeid', sa.Integer(), nullable=False),
    sa.Column('game', sa.String(length=32), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('type', sa.String(length=64), nullable=False),
    sa.Column('data', sa.JSON(), nullable=False),
    sa.UniqueConstraint('arcadeid', 'game', 'version', 'type', name='arcadeid_game_version_type')
    )
    op.create_table('audit',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('timestamp', sa.Integer(), nullable=False),
    sa.Column('userid', mysql.BIGINT(unsigned=True), nullable=True),
    sa.Column('arcadeid', sa.Integer(), nullable=True),
    sa.Column('type', sa.String(length=64), nullable=False),
    sa.Column('data', sa.JSON(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_arcadeid'), 'audit', ['arcadeid'], unique=False)
    op.create_index(op.f('ix_audit_timestamp'), 'audit', ['timestamp'], unique=False)
    op.create_index(op.f('ix_audit_type'), 'audit', ['type'], unique=False)
    op.create_index(op.f('ix_audit_userid'), 'audit', ['userid'], unique=False)
    op.create_table('balance',
    sa.Column('userid', mysql.BIGINT(unsigned=True), nullable=False),
    sa.Column('arcadeid', sa.Integer(), nullable=False),
    sa.Column('balance', sa.Integer(), nullable=False),
    sa.UniqueConstraint('userid', 'arcadeid', name='balance_userid_arcadeid')
    )
    op.create_table('card',
    sa.Column('id', sa.String(length=16), nullable=False),
    sa.Column('userid', mysql.BIGINT(unsigned=True), nullable=False),
    sa.UniqueConstraint('id')
    )
    op.create_index(op.f('ix_card_userid'), 'card', ['userid'], unique=False)
    op.create_table('catalog',
    sa.Column('game', sa.String(length=32), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('type', sa.String(length=64), nullable=False),
    sa.Column('data', sa.JSON(), nullable=False),
    sa.UniqueConstraint('game', 'version', 'id', 'type', name='game_version_id_type')
    )
    op.create_table('client',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('timestamp', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('token', sa.String(length=36), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_client_timestamp'), 'client', ['timestamp'], unique=False)
    op.create_table('extid',
    sa.Column('game', sa.String(length=32), nullable=False),
    sa.Column('extid', sa.Integer(), nullable=False),
    sa.Column('userid', mysql.BIGINT(unsigned=True), nullable=False),
    sa.UniqueConstraint('extid'),
    sa.UniqueConstraint('game', 'userid', name='extid_game_userid')
    )
    op.create_table('game_settings',
    sa.Column('game', sa.String(length=32), nullable=False),
    sa.Column('userid', mysql.BIGINT(unsigned=True), nullable=False),
    sa.Column('data', sa.JSON(), nullable=False),
    sa.UniqueConstraint('game', 'userid', name='gs_game_userid')
    )
    op.create_table('link',
    sa.Column('game', sa.String(length=32), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('userid', mysql.BIGINT(unsigned=True), nullable=False),
    sa.Column('type', sa.String(length=64), nullable=False),
    sa.Column('other_userid', mysql.BIGINT(unsigned=True), nullable=False),
    sa.Column('data', sa.JSON(), nullable=False),
    sa.UniqueConstraint('game', 'version', 'userid', 'type', 'other_userid', name='game_version_userid_type_other_uuserid')
    )
    op.create_table('lobby',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('game', sa.String(length=32), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('userid', mysql.BIGINT(unsigned=True), nullable=False),
    sa.Column('time', sa.Integer(), nullable=False),
    sa.Column('data', sa.JSON(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('game', 'version', 'userid', name='lobby_game_version_userid')
    )
    op.create_index(op.f('ix_lobby_time'), 'lobby', ['time'], unique=False)
    op.create_table('machine',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('pcbid', sa.String(length=20), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('description', sa.String(length=255), nullable=False),
    sa.Column('arcadeid', sa.Integer(), nullable=True),
    sa.Column('port', sa.Integer(), nullable=False),
    sa.Column('game', sa.String(length=20), nullable=True),
    sa.Column('version', sa.Integer(), nullable=True),
    sa.Column('data', sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('pcbid'),
    sa.UniqueConstraint('port')
    )
    op.create_table('music',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('songid', sa.Integer(), nullable=False),
    sa.Column('chart', sa.Integer(), nullable=False),
    sa.Column('game', sa.String(length=32), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=True),
    sa.Column('artist', sa.String(length=255), nullable=True),
    sa.Column('genre', sa.String(length=255), nullable=True),
    sa.Column('data', sa.JSON(), nullable=True),
    sa.UniqueConstraint('songid', 'chart', 'game', 'version', name='songid_chart_game_version')
    )
    op.create_index(op.f('ix_music_game'), 'music', ['game'], unique=False)
    op.create_index(op.f('ix_music_id'), 'music', ['id'], unique=False)
    op.create_index(op.f('ix_music_version'), 'music', ['version'], unique=False)
    op.create_table('news',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('timestamp', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('body', sa.Text(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_news_timestamp'), 'news', ['timestamp'], unique=False)
    op.create_table('playsession',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('game', sa.String(length=32), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('userid', mysql.BIGINT(unsigned=True), nullable=False),
    sa.Column('time', sa.Integer(), nullable=False),
    sa.Column('data', sa.JSON(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('game', 'version', 'userid', name='ps_game_version_userid')
    )
    op.create_index(op.f('ix_playsession_time'), 'playsession', ['time'], unique=False)
    op.create_table('profile',
    sa.Column('refid', sa.String(length=16), nullable=False),
    sa.Column('data', sa.JSON(), nullable=False),
    sa.UniqueConstraint('refid')
    )
    op.create_table('refid',
    sa.Column('game', sa.String(length=32), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('refid', sa.String(length=16), nullable=False),
    sa.Column('userid', mysql.BIGINT(unsigned=True), nullable=False),
    sa.UniqueConstraint('game', 'version', 'userid', name='game_version_userid'),
    sa.UniqueConstraint('refid')
    )
    op.create_table('scheduled_work',
    sa.Column('game', sa.String(length=32), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=32), nullable=False),
    sa.Column('schedule', sa.String(length=32), nullable=False),
    sa.Column('year', sa.Integer(), nullable=True),
    sa.Column('day', sa.Integer(), nullable=True),
    sa.UniqueConstraint('game', 'version', 'name', 'schedule', name='game_version_name_schedule')
    )
    op.create_table('score',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('userid', mysql.BIGINT(unsigned=True), nullable=False),
    sa.Column('musicid', sa.Integer(), nullable=False),
    sa.Column('points', sa.Integer(), nullable=False),
    sa.Column('timestamp', sa.Integer(), nullable=False),
    sa.Column('update', sa.Integer(), nullable=False),
    sa.Column('lid', sa.Integer(), nullable=False),
    sa.Column('data', sa.JSON(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('userid', 'musicid', name='userid_musicid')
    )
    op.create_index(op.f('ix_score_lid'), 'score', ['lid'], unique=False)
    op.create_index(op.f('ix_score_musicid'), 'score', ['musicid'], unique=False)
    op.create_index(op.f('ix_score_points'), 'score', ['points'], unique=False)
    op.create_index(op.f('ix_score_timestamp'), 'score', ['timestamp'], unique=False)
    op.create_index(op.f('ix_score_update'), 'score', ['update'], unique=False)
    op.create_table('score_history',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('userid', mysql.BIGINT(unsigned=True), nullable=False),
    sa.Column('musicid', sa.Integer(), nullable=False),
    sa.Column('points', sa.Integer(), nullable=False),
    sa.Column('timestamp', sa.Integer(), nullable=False),
    sa.Column('lid', sa.Integer(), nullable=False),
    sa.Column('new_record', sa.Integer(), nullable=False),
    sa.Column('data', sa.JSON(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('userid', 'musicid', 'timestamp', name='userid_musicid_timestamp')
    )
    op.create_index(op.f('ix_score_history_lid'), 'score_history', ['lid'], unique=False)
    op.create_index(op.f('ix_score_history_musicid'), 'score_history', ['musicid'], unique=False)
    op.create_index(op.f('ix_score_history_timestamp'), 'score_history', ['timestamp'], unique=False)
    op.create_table('series_achievement',
    sa.Column('game', sa.String(length=32), nullable=False),
    sa.Column('userid', mysql.BIGINT(unsigned=True), nullable=False),
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('type', sa.String(length=64), nullable=False),
    sa.Column('data', sa.JSON(), nullable=False),
    sa.UniqueConstraint('game', 'userid', 'id', 'type', name='game_userid_id_type')
    )
    op.create_table('server',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('timestamp', sa.Integer(), nullable=False),
    sa.Column('uri', sa.String(length=1024), nullable=False),
    sa.Column('token', sa.String(length=64), nullable=False),
    sa.Column('config', sa.Integer(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_server_timestamp'), 'server', ['timestamp'], unique=False)
    op.create_table('session',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('type', sa.String(length=32), nullable=False),
    sa.Column('session', sa.String(length=32), nullable=False),
    sa.Column('expiration', sa.Integer(), nullable=True),
    sa.UniqueConstraint('session')
    )
    op.create_table('time_based_achievement',
    sa.Column('refid', sa.String(length=16), nullable=False),
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('type', sa.String(length=64), nullable=False),
    sa.Column('timestamp', sa.Integer(), nullable=False),
    sa.Column('data', sa.JSON(), nullable=False),
    sa.UniqueConstraint('refid', 'id', 'type', 'timestamp', name='refid_id_type_timestamp')
    )
    op.create_index(op.f('ix_time_based_achievement_timestamp'), 'time_based_achievement', ['timestamp'], unique=False)
    op.create_table('time_sensitive_settings',
    sa.Column('game', sa.String(length=32), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=32), nullable=False),
    sa.Column('start_time', sa.Integer(), nullable=False),
    sa.Column('end_time', sa.Integer(), nullable=False),
    sa.Column('data', sa.JSON(), nullable=False),
    sa.UniqueConstraint('game', 'version', 'name', 'start_time', name='game_version_name_start_time')
    )
    op.create_index(op.f('ix_time_sensitive_settings_end_time'), 'time_sensitive_settings', ['end_time'], unique=False)
    op.create_index(op.f('ix_time_sensitive_settings_start_time'), 'time_sensitive_settings', ['start_time'], unique=False)
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('pin', sa.String(length=4), nullable=False),
    sa.Column('username', sa.String(length=255), nullable=True),
    sa.Column('password', sa.String(length=255), nullable=True),
    sa.Column('email', sa.String(length=255), nullable=True),
    sa.Column('admin', sa.Integer(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('username')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('user')
    op.drop_index(op.f('ix_time_sensitive_settings_start_time'), table_name='time_sensitive_settings')
    op.drop_index(op.f('ix_time_sensitive_settings_end_time'), table_name='time_sensitive_settings')
    op.drop_table('time_sensitive_settings')
    op.drop_index(op.f('ix_time_based_achievement_timestamp'), table_name='time_based_achievement')
    op.drop_table('time_based_achievement')
    op.drop_table('session')
    op.drop_index(op.f('ix_server_timestamp'), table_name='server')
    op.drop_table('server')
    op.drop_table('series_achievement')
    op.drop_index(op.f('ix_score_history_timestamp'), table_name='score_history')
    op.drop_index(op.f('ix_score_history_musicid'), table_name='score_history')
    op.drop_index(op.f('ix_score_history_lid'), table_name='score_history')
    op.drop_table('score_history')
    op.drop_index(op.f('ix_score_update'), table_name='score')
    op.drop_index(op.f('ix_score_timestamp'), table_name='score')
    op.drop_index(op.f('ix_score_points'), table_name='score')
    op.drop_index(op.f('ix_score_musicid'), table_name='score')
    op.drop_index(op.f('ix_score_lid'), table_name='score')
    op.drop_table('score')
    op.drop_table('scheduled_work')
    op.drop_table('refid')
    op.drop_table('profile')
    op.drop_index(op.f('ix_playsession_time'), table_name='playsession')
    op.drop_table('playsession')
    op.drop_index(op.f('ix_news_timestamp'), table_name='news')
    op.drop_table('news')
    op.drop_index(op.f('ix_music_version'), table_name='music')
    op.drop_index(op.f('ix_music_id'), table_name='music')
    op.drop_index(op.f('ix_music_game'), table_name='music')
    op.drop_table('music')
    op.drop_table('machine')
    op.drop_index(op.f('ix_lobby_time'), table_name='lobby')
    op.drop_table('lobby')
    op.drop_table('link')
    op.drop_table('game_settings')
    op.drop_table('extid')
    op.drop_index(op.f('ix_client_timestamp'), table_name='client')
    op.drop_table('client')
    op.drop_table('catalog')
    op.drop_index(op.f('ix_card_userid'), table_name='card')
    op.drop_table('card')
    op.drop_table('balance')
    op.drop_index(op.f('ix_audit_userid'), table_name='audit')
    op.drop_index(op.f('ix_audit_type'), table_name='audit')
    op.drop_index(op.f('ix_audit_timestamp'), table_name='audit')
    op.drop_index(op.f('ix_audit_arcadeid'), table_name='audit')
    op.drop_table('audit')
    op.drop_table('arcade_settings')
    op.drop_table('arcade_owner')
    op.drop_table('arcade')
    op.drop_table('achievement')
    # ### end Alembic commands ###