# vim: set fileencoding=utf-8
import re
from typing import Any, Dict
from flask import Blueprint, request, Response, url_for, abort, g  # type: ignore

from bemani.common import GameConstants
from bemani.data import UserID
from bemani.frontend.app import loginrequired, jsonify, render_react
from bemani.frontend.museca.museca import MusecaFrontend
from bemani.frontend.templates import templates_location
from bemani.frontend.static import static_location

museca_pages = Blueprint(
    'museca_pages',
    __name__,
    url_prefix='/museca',
    template_folder=templates_location,
    static_folder=static_location,
)


@museca_pages.route('/scores')
@loginrequired
def viewnetworkscores() -> Response:
    # Only load the last 100 results for the initial fetch, so we can render faster
    frontend = MusecaFrontend(g.data, g.config, g.cache)
    network_scores = frontend.get_network_scores(limit=100)
    if len(network_scores['attempts']) > 10:
        network_scores['attempts'] = frontend.round_to_ten(network_scores['attempts'])

    return render_react(
        'Global MÚSECA Scores',
        'museca/scores.react.js',
        {
            'attempts': network_scores['attempts'],
            'songs': frontend.get_all_songs(),
            'players': network_scores['players'],
            'shownames': True,
            'shownewrecords': False,
        },
        {
            'refresh': url_for('museca_pages.listnetworkscores'),
            'player': url_for('museca_pages.viewplayer', userid=-1),
            'individual_score': url_for('museca_pages.viewtopscores', musicid=-1),
        },
    )


@museca_pages.route('/scores/list')
@jsonify
@loginrequired
def listnetworkscores() -> Dict[str, Any]:
    frontend = MusecaFrontend(g.data, g.config, g.cache)
    return frontend.get_network_scores()


@museca_pages.route('/scores/<int:userid>')
@loginrequired
def viewscores(userid: UserID) -> Response:
    frontend = MusecaFrontend(g.data, g.config, g.cache)
    info = frontend.get_latest_player_info([userid]).get(userid)
    if info is None:
        abort(404)

    scores = frontend.get_scores(userid, limit=100)
    if len(scores) > 10:
        scores = frontend.round_to_ten(scores)

    return render_react(
        f'{info["name"]}\'s MÚSECA Scores',
        'museca/scores.react.js',
        {
            'attempts': scores,
            'songs': frontend.get_all_songs(),
            'players': {},
            'shownames': False,
            'shownewrecords': True,
        },
        {
            'refresh': url_for('museca_pages.listscores', userid=userid),
            'player': url_for('museca_pages.viewplayer', userid=-1),
            'individual_score': url_for('museca_pages.viewtopscores', musicid=-1),
        },
    )


@museca_pages.route('/scores/<int:userid>/list')
@jsonify
@loginrequired
def listscores(userid: UserID) -> Dict[str, Any]:
    frontend = MusecaFrontend(g.data, g.config, g.cache)
    return {
        'attempts': frontend.get_scores(userid),
        'players': {},
    }


@museca_pages.route('/records')
@loginrequired
def viewnetworkrecords() -> Response:
    frontend = MusecaFrontend(g.data, g.config, g.cache)
    network_records = frontend.get_network_records()
    versions = {version: name for (game, version, name) in frontend.all_games()}
    versions[0] = 'CS and Licenses'

    return render_react(
        'Global MÚSECA Records',
        'museca/records.react.js',
        {
            'records': network_records['records'],
            'songs': frontend.get_all_songs(),
            'players': network_records['players'],
            'versions': versions,
            'shownames': True,
            'showpersonalsort': False,
            'filterempty': False,
        },
        {
            'refresh': url_for('museca_pages.listnetworkrecords'),
            'player': url_for('museca_pages.viewplayer', userid=-1),
            'individual_score': url_for('museca_pages.viewtopscores', musicid=-1),
        },
    )


@museca_pages.route('/records/list')
@jsonify
@loginrequired
def listnetworkrecords() -> Dict[str, Any]:
    frontend = MusecaFrontend(g.data, g.config, g.cache)
    return frontend.get_network_records()


@museca_pages.route('/records/<int:userid>')
@loginrequired
def viewrecords(userid: UserID) -> Response:
    frontend = MusecaFrontend(g.data, g.config, g.cache)
    info = frontend.get_latest_player_info([userid]).get(userid)
    if info is None:
        abort(404)
    versions = {version: name for (game, version, name) in frontend.all_games()}

    return render_react(
        f'{info["name"]}\'s MÚSECA Records',
        'museca/records.react.js',
        {
            'records': frontend.get_records(userid),
            'songs': frontend.get_all_songs(),
            'players': {},
            'versions': versions,
            'shownames': False,
            'showpersonalsort': True,
            'filterempty': True,
        },
        {
            'refresh': url_for('museca_pages.listrecords', userid=userid),
            'player': url_for('museca_pages.viewplayer', userid=-1),
            'individual_score': url_for('museca_pages.viewtopscores', musicid=-1),
        },
    )


@museca_pages.route('/records/<int:userid>/list')
@jsonify
@loginrequired
def listrecords(userid: UserID) -> Dict[str, Any]:
    frontend = MusecaFrontend(g.data, g.config, g.cache)
    return {
        'records': frontend.get_records(userid),
        'players': {},
    }


@museca_pages.route('/topscores/<int:musicid>')
@loginrequired
def viewtopscores(musicid: int) -> Response:
    # We just want to find the latest mix that this song exists in
    frontend = MusecaFrontend(g.data, g.config, g.cache)
    versions = sorted(
        [version for (game, version, name) in frontend.all_games()],
        reverse=True,
    )
    name = None
    artist = None
    difficulties = [0, 0, 0, 0, 0]

    for version in versions:
        for omniadd in [0, 10000]:
            for chart in [0, 1, 2, 3, 4]:
                details = g.data.local.music.get_song(GameConstants.MUSECA, version + omniadd, musicid, chart)
                if details is not None:
                    if name is None:
                        name = details.name
                    if artist is None:
                        artist = details.artist
                    if difficulties[chart] == 0:
                        difficulties[chart] = details.data.get_int('difficulty')

    if name is None:
        # Not a real song!
        abort(404)

    top_scores = frontend.get_top_scores(musicid)

    return render_react(
        f'Top MÚSECA Scores for {artist} - {name}',
        'museca/topscores.react.js',
        {
            'name': name,
            'artist': artist,
            'difficulties': difficulties,
            'players': top_scores['players'],
            'topscores': top_scores['topscores'],
        },
        {
            'refresh': url_for('museca_pages.listtopscores', musicid=musicid),
            'player': url_for('museca_pages.viewplayer', userid=-1),
        },
    )


@museca_pages.route('/topscores/<int:musicid>/list')
@jsonify
@loginrequired
def listtopscores(musicid: int) -> Dict[str, Any]:
    frontend = MusecaFrontend(g.data, g.config, g.cache)
    return frontend.get_top_scores(musicid)


@museca_pages.route('/players')
@loginrequired
def viewplayers() -> Response:
    frontend = MusecaFrontend(g.data, g.config, g.cache)
    return render_react(
        'All MÚSECA Players',
        'museca/allplayers.react.js',
        {
            'players': frontend.get_all_players()
        },
        {
            'refresh': url_for('museca_pages.listplayers'),
            'player': url_for('museca_pages.viewplayer', userid=-1),
        },
    )


@museca_pages.route('/players/list')
@jsonify
@loginrequired
def listplayers() -> Dict[str, Any]:
    frontend = MusecaFrontend(g.data, g.config, g.cache)
    return {
        'players': frontend.get_all_players(),
    }


@museca_pages.route('/players/<int:userid>')
@loginrequired
def viewplayer(userid: UserID) -> Response:
    frontend = MusecaFrontend(g.data, g.config, g.cache)
    info = frontend.get_all_player_info([userid])[userid]
    if not info:
        abort(404)
    latest_version = sorted(info.keys(), reverse=True)[0]

    return render_react(
        f'{info[latest_version]["name"]}\'s MÚSECA Profile',
        'museca/player.react.js',
        {
            'playerid': userid,
            'own_profile': userid == g.userID,
            'player': info,
            'versions': {version: name for (game, version, name) in frontend.all_games()},
        },
        {
            'refresh': url_for('museca_pages.listplayer', userid=userid),
            'records': url_for('museca_pages.viewrecords', userid=userid),
            'scores': url_for('museca_pages.viewscores', userid=userid),
        },
    )


@museca_pages.route('/players/<int:userid>/list')
@jsonify
@loginrequired
def listplayer(userid: UserID) -> Dict[str, Any]:
    frontend = MusecaFrontend(g.data, g.config, g.cache)
    info = frontend.get_all_player_info([userid])[userid]

    return {
        'player': info,
    }


@museca_pages.route('/options')
@loginrequired
def viewsettings() -> Response:
    frontend = MusecaFrontend(g.data, g.config, g.cache)
    userid = g.userID
    info = frontend.get_all_player_info([userid])[userid]
    if not info:
        abort(404)

    return render_react(
        'MÚSECA Game Settings',
        'museca/settings.react.js',
        {
            'player': info,
            'versions': {version: name for (game, version, name) in frontend.all_games()},
        },
        {
            'updatename': url_for('museca_pages.updatename'),
        },
    )


@museca_pages.route('/options/name/update', methods=['POST'])
@jsonify
@loginrequired
def updatename() -> Dict[str, Any]:
    version = int(request.get_json()['version'])
    name = request.get_json()['name']
    user = g.data.local.user.get_user(g.userID)
    if user is None:
        raise Exception('Unable to find user to update!')

    # Grab profile and update name
    profile = g.data.local.user.get_profile(GameConstants.MUSECA, version, user.id)
    if profile is None:
        raise Exception('Unable to find profile to update!')
    if len(name) == 0 or len(name) > 8:
        raise Exception('Invalid profile name!')
    if re.match(
        "^[" +
        "0-9" +
        "A-Z" +
        "!?#$&*-. " +
        "]*$",
        name,
    ) is None:
        raise Exception('Invalid profile name!')
    profile.replace_str('name', name)
    g.data.local.user.put_profile(GameConstants.MUSECA, version, user.id, profile)

    # Return that we updated
    return {
        'version': version,
        'name': name,
    }
