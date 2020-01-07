# vim: set fileencoding=utf-8
import re
from typing import Any, Dict
from flask import Blueprint, request, Response, url_for, abort, g  # type: ignore

from bemani.common import GameConstants
from bemani.data import UserID
from bemani.frontend.app import loginrequired, jsonify, render_react
from bemani.frontend.jubeat.jubeat import JubeatFrontend
from bemani.frontend.templates import templates_location
from bemani.frontend.static import static_location

jubeat_pages = Blueprint(
    'jubeat_pages',
    __name__,
    url_prefix='/jubeat',
    template_folder=templates_location,
    static_folder=static_location,
)


@jubeat_pages.route('/scores')
@loginrequired
def viewnetworkscores() -> Response:
    # Only load the last 100 results for the initial fetch, so we can render faster
    frontend = JubeatFrontend(g.data, g.config, g.cache)
    network_scores = frontend.get_network_scores(limit=100)
    if len(network_scores['attempts']) > 10:
        network_scores['attempts'] = frontend.round_to_ten(network_scores['attempts'])

    return render_react(
        'Global Jubeat Scores',
        'jubeat/scores.react.js',
        {
            'attempts': network_scores['attempts'],
            'songs': frontend.get_all_songs(),
            'players': network_scores['players'],
            'versions': {version: name for (game, version, name) in frontend.sanitized_games()},
            'shownames': True,
            'shownewrecords': False,
        },
        {
            'refresh': url_for('jubeat_pages.listnetworkscores'),
            'player': url_for('jubeat_pages.viewplayer', userid=-1),
            'individual_score': url_for('jubeat_pages.viewtopscores', musicid=-1),
        },
    )


@jubeat_pages.route('/scores/list')
@jsonify
@loginrequired
def listnetworkscores() -> Dict[str, Any]:
    frontend = JubeatFrontend(g.data, g.config, g.cache)
    return frontend.get_network_scores()


@jubeat_pages.route('/scores/<int:userid>')
@loginrequired
def viewscores(userid: UserID) -> Response:
    frontend = JubeatFrontend(g.data, g.config, g.cache)
    info = frontend.get_latest_player_info([userid]).get(userid)
    if info is None:
        abort(404)

    scores = frontend.get_scores(userid, limit=100)
    if len(scores) > 10:
        scores = frontend.round_to_ten(scores)

    return render_react(
        f'{info["name"]}\'s Jubeat Scores',
        'jubeat/scores.react.js',
        {
            'attempts': scores,
            'songs': frontend.get_all_songs(),
            'players': {},
            'versions': {version: name for (game, version, name) in frontend.sanitized_games()},
            'shownames': False,
            'shownewrecords': True,
        },
        {
            'refresh': url_for('jubeat_pages.listscores', userid=userid),
            'player': url_for('jubeat_pages.viewplayer', userid=-1),
            'individual_score': url_for('jubeat_pages.viewtopscores', musicid=-1),
        },
    )


@jubeat_pages.route('/scores/<int:userid>/list')
@jsonify
@loginrequired
def listscores(userid: UserID) -> Dict[str, Any]:
    frontend = JubeatFrontend(g.data, g.config, g.cache)
    return {
        'attempts': frontend.get_scores(userid),
        'players': {},
    }


@jubeat_pages.route('/records')
@loginrequired
def viewnetworkrecords() -> Response:
    frontend = JubeatFrontend(g.data, g.config, g.cache)
    network_records = frontend.get_network_records()

    return render_react(
        'Global Jubeat Records',
        'jubeat/records.react.js',
        {
            'records': network_records['records'],
            'songs': frontend.get_all_songs(),
            'players': network_records['players'],
            'versions': {version: name for (game, version, name) in frontend.sanitized_games()},
            'shownames': True,
            'showpersonalsort': False,
            'filterempty': False,
        },
        {
            'refresh': url_for('jubeat_pages.listnetworkrecords'),
            'player': url_for('jubeat_pages.viewplayer', userid=-1),
            'individual_score': url_for('jubeat_pages.viewtopscores', musicid=-1),
        },
    )


@jubeat_pages.route('/records/list')
@jsonify
@loginrequired
def listnetworkrecords() -> Dict[str, Any]:
    frontend = JubeatFrontend(g.data, g.config, g.cache)
    return frontend.get_network_records()


@jubeat_pages.route('/records/<int:userid>')
@loginrequired
def viewrecords(userid: UserID) -> Response:
    frontend = JubeatFrontend(g.data, g.config, g.cache)
    info = frontend.get_latest_player_info([userid]).get(userid)
    if info is None:
        abort(404)

    return render_react(
        f'{info["name"]}\'s Jubeat Records',
        'jubeat/records.react.js',
        {
            'records': frontend.get_records(userid),
            'songs': frontend.get_all_songs(),
            'players': {},
            'versions': {version: name for (game, version, name) in frontend.sanitized_games()},
            'shownames': False,
            'showpersonalsort': True,
            'filterempty': True,
        },
        {
            'refresh': url_for('jubeat_pages.listrecords', userid=userid),
            'player': url_for('jubeat_pages.viewplayer', userid=-1),
            'individual_score': url_for('jubeat_pages.viewtopscores', musicid=-1),
        },
    )


@jubeat_pages.route('/records/<int:userid>/list')
@jsonify
@loginrequired
def listrecords(userid: UserID) -> Dict[str, Any]:
    frontend = JubeatFrontend(g.data, g.config, g.cache)
    return {
        'records': frontend.get_records(userid),
        'players': {},
    }


@jubeat_pages.route('/topscores/<int:musicid>')
@loginrequired
def viewtopscores(musicid: int) -> Response:
    # We just want to find the latest mix that this song exists in
    frontend = JubeatFrontend(g.data, g.config, g.cache)
    versions = sorted(
        [version for (game, version, name) in frontend.all_games()],
        reverse=True,
    )
    name = None
    artist = None
    genre = None
    difficulties = [0, 0, 0]

    for version in versions:
        for chart in [0, 1, 2]:
            details = g.data.local.music.get_song(GameConstants.JUBEAT, version, musicid, chart)
            if details is not None:
                name = details.name
                artist = details.artist
                genre = details.genre
                difficulties[chart] = details.data.get_int('difficulty', 13)

    if name is None:
        # Not a real song!
        abort(404)

    top_scores = frontend.get_top_scores(musicid)

    return render_react(
        f'Top Jubeat Scores for {artist} - {name}',
        'jubeat/topscores.react.js',
        {
            'name': name,
            'artist': artist,
            'genre': genre,
            'difficulties': difficulties,
            'players': top_scores['players'],
            'topscores': top_scores['topscores'],
        },
        {
            'refresh': url_for('jubeat_pages.listtopscores', musicid=musicid),
            'player': url_for('jubeat_pages.viewplayer', userid=-1),
        },
    )


@jubeat_pages.route('/topscores/<int:musicid>/list')
@jsonify
@loginrequired
def listtopscores(musicid: int) -> Dict[str, Any]:
    frontend = JubeatFrontend(g.data, g.config, g.cache)
    return frontend.get_top_scores(musicid)


@jubeat_pages.route('/players')
@loginrequired
def viewplayers() -> Response:
    frontend = JubeatFrontend(g.data, g.config, g.cache)
    return render_react(
        'All Jubeat Players',
        'jubeat/allplayers.react.js',
        {
            'players': frontend.get_all_players()
        },
        {
            'refresh': url_for('jubeat_pages.listplayers'),
            'player': url_for('jubeat_pages.viewplayer', userid=-1),
        },
    )


@jubeat_pages.route('/players/list')
@jsonify
@loginrequired
def listplayers() -> Dict[str, Any]:
    frontend = JubeatFrontend(g.data, g.config, g.cache)
    return {
        'players': frontend.get_all_players(),
    }


@jubeat_pages.route('/players/<int:userid>')
@loginrequired
def viewplayer(userid: UserID) -> Response:
    frontend = JubeatFrontend(g.data, g.config, g.cache)
    info = frontend.get_all_player_info([userid])[userid]
    if not info:
        abort(404)
    latest_version = sorted(info.keys(), reverse=True)[0]

    return render_react(
        f'{info[latest_version]["name"]}\'s Jubeat Profile',
        'jubeat/player.react.js',
        {
            'playerid': userid,
            'own_profile': userid == g.userID,
            'player': info,
            'versions': {version: name for (game, version, name) in frontend.all_games()},
        },
        {
            'refresh': url_for('jubeat_pages.listplayer', userid=userid),
            'records': url_for('jubeat_pages.viewrecords', userid=userid),
            'scores': url_for('jubeat_pages.viewscores', userid=userid),
        },
    )


@jubeat_pages.route('/players/<int:userid>/list')
@jsonify
@loginrequired
def listplayer(userid: UserID) -> Dict[str, Any]:
    frontend = JubeatFrontend(g.data, g.config, g.cache)
    info = frontend.get_all_player_info([userid])[userid]

    return {
        'player': info,
    }


@jubeat_pages.route('/options')
@loginrequired
def viewsettings() -> Response:
    frontend = JubeatFrontend(g.data, g.config, g.cache)
    userid = g.userID
    info = frontend.get_all_player_info([userid])[userid]
    if not info:
        abort(404)

    return render_react(
        'Jubeat Game Settings',
        'jubeat/settings.react.js',
        {
            'player': info,
            'versions': {version: name for (game, version, name) in frontend.all_games()},
        },
        {
            'updatename': url_for('jubeat_pages.updatename'),
        },
    )


@jubeat_pages.route('/options/name/update', methods=['POST'])
@jsonify
@loginrequired
def updatename() -> Dict[str, Any]:
    version = int(request.get_json()['version'])
    name = request.get_json()['name']
    user = g.data.local.user.get_user(g.userID)
    if user is None:
        raise Exception('Unable to find user to update!')

    # Grab profile and update name
    profile = g.data.local.user.get_profile(GameConstants.JUBEAT, version, user.id)
    if profile is None:
        raise Exception('Unable to find profile to update!')
    if len(name) == 0 or len(name) > 8:
        raise Exception('Invalid profile name!')
    if re.match(r'^[-&\.\*A-Z0-9]*$', name) is None:
        raise Exception('Invalid profile name!')
    profile.replace_str('name', name)
    g.data.local.user.put_profile(GameConstants.JUBEAT, version, user.id, profile)

    # Return that we updated
    return {
        'version': version,
        'name': name,
    }
