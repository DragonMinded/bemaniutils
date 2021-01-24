# vim: set fileencoding=utf-8
import re
from typing import Any, Dict
from flask import Blueprint, request, Response, url_for, abort, g  # type: ignore

from bemani.common import ID, GameConstants, VersionConstants
from bemani.data import UserID
from bemani.frontend.app import loginrequired, jsonify, render_react
from bemani.frontend.popn.popn import PopnMusicFrontend
from bemani.frontend.templates import templates_location
from bemani.frontend.static import static_location

popn_pages = Blueprint(
    'popn_pages',
    __name__,
    url_prefix='/popn',
    template_folder=templates_location,
    static_folder=static_location,
)


@popn_pages.route('/scores')
@loginrequired
def viewnetworkscores() -> Response:
    # Only load the last 100 results for the initial fetch, so we can render faster
    frontend = PopnMusicFrontend(g.data, g.config, g.cache)
    network_scores = frontend.get_network_scores(limit=100)
    if len(network_scores['attempts']) > 10:
        network_scores['attempts'] = frontend.round_to_ten(network_scores['attempts'])

    return render_react(
        'Global Pop\'n Music Scores',
        'popn/scores.react.js',
        {
            'attempts': network_scores['attempts'],
            'songs': frontend.get_all_songs(),
            'players': network_scores['players'],
            'shownames': True,
            'shownewrecords': False,
        },
        {
            'refresh': url_for('popn_pages.listnetworkscores'),
            'player': url_for('popn_pages.viewplayer', userid=-1),
            'individual_score': url_for('popn_pages.viewtopscores', musicid=-1),
        },
    )


@popn_pages.route('/scores/list')
@jsonify
@loginrequired
def listnetworkscores() -> Dict[str, Any]:
    frontend = PopnMusicFrontend(g.data, g.config, g.cache)
    return frontend.get_network_scores()


@popn_pages.route('/scores/<int:userid>')
@loginrequired
def viewscores(userid: UserID) -> Response:
    frontend = PopnMusicFrontend(g.data, g.config, g.cache)
    info = frontend.get_latest_player_info([userid]).get(userid)
    if info is None:
        abort(404)

    scores = frontend.get_scores(userid, limit=100)
    if len(scores) > 10:
        scores = frontend.round_to_ten(scores)

    return render_react(
        f'{info["name"]}\'s Pop\'n Music Scores',
        'popn/scores.react.js',
        {
            'attempts': scores,
            'songs': frontend.get_all_songs(),
            'players': {},
            'shownames': False,
            'shownewrecords': True,
        },
        {
            'refresh': url_for('popn_pages.listscores', userid=userid),
            'player': url_for('popn_pages.viewplayer', userid=-1),
            'individual_score': url_for('popn_pages.viewtopscores', musicid=-1),
        },
    )


@popn_pages.route('/scores/<int:userid>/list')
@jsonify
@loginrequired
def listscores(userid: UserID) -> Dict[str, Any]:
    frontend = PopnMusicFrontend(g.data, g.config, g.cache)
    return {
        'attempts': frontend.get_scores(userid),
        'players': {},
    }


@popn_pages.route('/records')
@loginrequired
def viewnetworkrecords() -> Response:
    frontend = PopnMusicFrontend(g.data, g.config, g.cache)
    network_records = frontend.get_network_records()
    versions = {version: name for (game, version, name) in frontend.all_games()}

    return render_react(
        'Global Pop\'n Music Records',
        'popn/records.react.js',
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
            'refresh': url_for('popn_pages.listnetworkrecords'),
            'player': url_for('popn_pages.viewplayer', userid=-1),
            'individual_score': url_for('popn_pages.viewtopscores', musicid=-1),
        },
    )


@popn_pages.route('/records/list')
@jsonify
@loginrequired
def listnetworkrecords() -> Dict[str, Any]:
    frontend = PopnMusicFrontend(g.data, g.config, g.cache)
    return frontend.get_network_records()


@popn_pages.route('/records/<int:userid>')
@loginrequired
def viewrecords(userid: UserID) -> Response:
    frontend = PopnMusicFrontend(g.data, g.config, g.cache)
    info = frontend.get_latest_player_info([userid]).get(userid)
    if info is None:
        abort(404)
    versions = {version: name for (game, version, name) in frontend.all_games()}

    return render_react(
        f'{info["name"]}\'s Pop\'n Music Records',
        'popn/records.react.js',
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
            'refresh': url_for('popn_pages.listrecords', userid=userid),
            'player': url_for('popn_pages.viewplayer', userid=-1),
            'individual_score': url_for('popn_pages.viewtopscores', musicid=-1),
        },
    )


@popn_pages.route('/records/<int:userid>/list')
@jsonify
@loginrequired
def listrecords(userid: UserID) -> Dict[str, Any]:
    frontend = PopnMusicFrontend(g.data, g.config, g.cache)
    return {
        'records': frontend.get_records(userid),
        'players': {},
    }


@popn_pages.route('/topscores/<int:musicid>')
@loginrequired
def viewtopscores(musicid: int) -> Response:
    # We just want to find the latest mix that this song exists in
    frontend = PopnMusicFrontend(g.data, g.config, g.cache)
    versions = sorted(
        [version for (game, version, name) in frontend.all_games()],
        reverse=True,
    )
    name = None
    artist = None
    genre = None
    difficulties = [0, 0, 0, 0]

    for version in versions:
        for chart in [0, 1, 2, 3]:
            details = g.data.local.music.get_song(GameConstants.POPN_MUSIC, version, musicid, chart)
            if details is not None:
                if name is None:
                    name = details.name
                if artist is None:
                    artist = details.artist
                if genre is None:
                    genre = details.genre
                if difficulties[chart] == 0:
                    difficulties[chart] = details.data.get_int('difficulty')

    if name is None:
        # Not a real song!
        abort(404)

    top_scores = frontend.get_top_scores(musicid)

    return render_react(
        f'Top Pop\'n Music Scores for {artist} - {name}',
        'popn/topscores.react.js',
        {
            'name': name,
            'artist': artist,
            'genre': genre,
            'difficulties': difficulties,
            'players': top_scores['players'],
            'topscores': top_scores['topscores'],
        },
        {
            'refresh': url_for('popn_pages.listtopscores', musicid=musicid),
            'player': url_for('popn_pages.viewplayer', userid=-1),
        },
    )


@popn_pages.route('/topscores/<int:musicid>/list')
@jsonify
@loginrequired
def listtopscores(musicid: int) -> Dict[str, Any]:
    frontend = PopnMusicFrontend(g.data, g.config, g.cache)
    return frontend.get_top_scores(musicid)


@popn_pages.route('/players')
@loginrequired
def viewplayers() -> Response:
    frontend = PopnMusicFrontend(g.data, g.config, g.cache)
    return render_react(
        'All Pop\'n Music Players',
        'popn/allplayers.react.js',
        {
            'players': frontend.get_all_players()
        },
        {
            'refresh': url_for('popn_pages.listplayers'),
            'player': url_for('popn_pages.viewplayer', userid=-1),
        },
    )


@popn_pages.route('/players/list')
@jsonify
@loginrequired
def listplayers() -> Dict[str, Any]:
    frontend = PopnMusicFrontend(g.data, g.config, g.cache)
    return {
        'players': frontend.get_all_players(),
    }


@popn_pages.route('/players/<int:userid>')
@loginrequired
def viewplayer(userid: UserID) -> Response:
    frontend = PopnMusicFrontend(g.data, g.config, g.cache)
    info = frontend.get_all_player_info([userid])[userid]
    if not info:
        abort(404)
    latest_version = sorted(info.keys(), reverse=True)[0]

    return render_react(
        f'{info[latest_version]["name"]}\'s Pop\'n Music Profile',
        'popn/player.react.js',
        {
            'playerid': userid,
            'own_profile': userid == g.userID,
            'player': info,
            'versions': {version: name for (game, version, name) in frontend.all_games()},
        },
        {
            'refresh': url_for('popn_pages.listplayer', userid=userid),
            'records': url_for('popn_pages.viewrecords', userid=userid),
            'scores': url_for('popn_pages.viewscores', userid=userid),
        },
    )


@popn_pages.route('/players/<int:userid>/list')
@jsonify
@loginrequired
def listplayer(userid: UserID) -> Dict[str, Any]:
    frontend = PopnMusicFrontend(g.data, g.config, g.cache)
    info = frontend.get_all_player_info([userid])[userid]

    return {
        'player': info,
    }


@popn_pages.route('/options')
@loginrequired
def viewsettings() -> Response:
    frontend = PopnMusicFrontend(g.data, g.config, g.cache)
    userid = g.userID
    info = frontend.get_all_player_info([userid])[userid]
    if not info:
        abort(404)

    return render_react(
        'Pop\'n Music Game Settings',
        'popn/settings.react.js',
        {
            'player': info,
            'versions': {version: name for (game, version, name) in frontend.all_games()},
        },
        {
            'updatename': url_for('popn_pages.updatename'),
        },
    )


@popn_pages.route('/options/name/update', methods=['POST'])
@jsonify
@loginrequired
def updatename() -> Dict[str, Any]:
    version = int(request.get_json()['version'])
    name = request.get_json()['name']
    user = g.data.local.user.get_user(g.userID)
    if user is None:
        raise Exception('Unable to find user to update!')

    # Grab profile and update name
    profile = g.data.local.user.get_profile(GameConstants.POPN_MUSIC, version, user.id)
    if profile is None:
        raise Exception('Unable to find profile to update!')
    if len(name) == 0 or len(name) > 6:
        raise Exception('Invalid profile name!')
    if re.match(
        "^[" +
        "\uFF20-\uFF3A" +  # widetext A-Z and @
        "\uFF41-\uFF5A" +  # widetext a-z
        "\uFF10-\uFF19" +  # widetext 0-9
        "\uFF0C\uFF0E\uFF3F" +  # widetext ,._
        "\u3041-\u308D\u308F\u3092\u3093" +  # hiragana
        "\u30A1-\u30ED\u30EF\u30F2\u30F3\u30FC" +  # katakana
        "]*$",
        name,
    ) is None:
        raise Exception('Invalid profile name!')
    profile.replace_str('name', name)
    g.data.local.user.put_profile(GameConstants.POPN_MUSIC, version, user.id, profile)

    # Return that we updated
    return {
        'version': version,
        'name': name,
    }


@popn_pages.route('/rivals')
@loginrequired
def viewrivals() -> Response:
    frontend = PopnMusicFrontend(g.data, g.config, g.cache)
    rivals, playerinfo = frontend.get_rivals(g.userID)

    # There is no support for Rivals in Tune Street.
    if VersionConstants.POPN_MUSIC_TUNE_STREET in rivals:
        del rivals[VersionConstants.POPN_MUSIC_TUNE_STREET]

    return render_react(
        'Pop\'n Music Rivals',
        'popn/rivals.react.js',
        {
            'userid': str(g.userID),
            'rivals': rivals,
            'max_active_rivals': frontend.max_active_rivals,
            'players': playerinfo,
            'versions': {version: name for (game, version, name) in frontend.all_games()},
        },
        {
            'refresh': url_for('popn_pages.listrivals'),
            'search': url_for('popn_pages.searchrivals'),
            'player': url_for('popn_pages.viewplayer', userid=-1),
            'addrival': url_for('popn_pages.addrival'),
            'removerival': url_for('popn_pages.removerival'),
        },
    )


@popn_pages.route('/rivals/list')
@jsonify
@loginrequired
def listrivals() -> Dict[str, Any]:
    frontend = PopnMusicFrontend(g.data, g.config, g.cache)
    rivals, playerinfo = frontend.get_rivals(g.userID)

    # There is no support for Rivals in Tune Street.
    if VersionConstants.POPN_MUSIC_TUNE_STREET in rivals:
        del rivals[VersionConstants.POPN_MUSIC_TUNE_STREET]

    return {
        'rivals': rivals,
        'players': playerinfo,
    }


@popn_pages.route('/rivals/search', methods=['POST'])
@jsonify
@loginrequired
def searchrivals() -> Dict[str, Any]:
    frontend = PopnMusicFrontend(g.data, g.config, g.cache)
    version = int(request.get_json()['version'])
    name = request.get_json()['term']
    print(name)

    # Try to treat the term as an extid
    extid = ID.parse_extid(name)

    matches = set()
    profiles = g.data.remote.user.get_all_profiles(GameConstants.POPN_MUSIC, version)
    for (userid, profile) in profiles:
        if profile.get_int('extid') == extid or profile.get_str('name').lower() == name.lower():
            matches.add(userid)

    playerinfo = frontend.get_all_player_info(list(matches), allow_remote=True)
    return {
        'results': playerinfo,
    }


@popn_pages.route('/rivals/add', methods=['POST'])
@jsonify
@loginrequired
def addrival() -> Dict[str, Any]:
    frontend = PopnMusicFrontend(g.data, g.config, g.cache)
    version = int(request.get_json()['version'])
    other_userid = UserID(int(request.get_json()['userid']))
    userid = g.userID

    # Add this rival link
    profile = g.data.remote.user.get_profile(GameConstants.POPN_MUSIC, version, other_userid)
    if profile is None:
        raise Exception('Unable to find profile for rival!')

    g.data.local.user.put_link(
        GameConstants.POPN_MUSIC,
        version,
        userid,
        'rival',
        other_userid,
        {},
    )

    # Now return updated rival info
    rivals, playerinfo = frontend.get_rivals(userid)

    return {
        'rivals': rivals,
        'players': playerinfo,
    }


@popn_pages.route('/rivals/remove', methods=['POST'])
@jsonify
@loginrequired
def removerival() -> Dict[str, Any]:
    frontend = PopnMusicFrontend(g.data, g.config, g.cache)
    version = int(request.get_json()['version'])
    other_userid = UserID(int(request.get_json()['userid']))
    userid = g.userID

    # Remove this rival link
    g.data.local.user.destroy_link(
        GameConstants.POPN_MUSIC,
        version,
        userid,
        'rival',
        other_userid,
    )

    # Now return updated rival info
    rivals, playerinfo = frontend.get_rivals(userid)

    return {
        'rivals': rivals,
        'players': playerinfo,
    }
