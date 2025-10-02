# vim: set fileencoding=utf-8
import re
from typing import Any, Dict
from flask import Blueprint, request, Response, url_for, abort
from bemani.common import GameConstants
from bemani.data import UserID
from bemani.frontend.app import loginrequired, jsonify, render_react
from bemani.frontend.danevo.danevo import DanceEvolutionFrontend
from bemani.frontend.templates import templates_location
from bemani.frontend.static import static_location
from bemani.frontend.types import g


danevo_pages = Blueprint(
    "danevo_pages",
    __name__,
    url_prefix=f"/{GameConstants.DANCE_EVOLUTION.value}",
    template_folder=templates_location,
    static_folder=static_location,
)


@danevo_pages.route("/records")
@loginrequired
def viewnetworkrecords() -> Response:
    frontend = DanceEvolutionFrontend(g.data, g.config, g.cache)
    network_records = frontend.get_network_records()
    versions = {version: name for (game, version, name) in frontend.all_games()}

    return render_react(
        "Global Dance Evolution Records",
        "danevo/records.react.js",
        {
            "records": network_records["records"],
            "songs": frontend.get_all_songs(),
            "players": network_records["players"],
            "versions": versions,
            "shownames": True,
            "showpersonalsort": False,
            "filterempty": False,
        },
        {
            "refresh": url_for("danevo_pages.listnetworkrecords"),
            "player": url_for("danevo_pages.viewplayer", userid=-1),
            "individual_score": url_for("danevo_pages.viewtopscores", musicid=-1),
        },
    )


@danevo_pages.route("/records/list")
@jsonify
@loginrequired
def listnetworkrecords() -> Dict[str, Any]:
    frontend = DanceEvolutionFrontend(g.data, g.config, g.cache)
    return frontend.get_network_records()


@danevo_pages.route("/records/<int:userid>")
@loginrequired
def viewrecords(userid: UserID) -> Response:
    frontend = DanceEvolutionFrontend(g.data, g.config, g.cache)
    info = frontend.get_latest_player_info([userid]).get(userid)
    if info is None:
        abort(404)
    versions = {version: name for (game, version, name) in frontend.all_games()}

    return render_react(
        f'{info["name"]}\'s Dance Evolution Records',
        "danevo/records.react.js",
        {
            "records": frontend.get_records(userid),
            "songs": frontend.get_all_songs(),
            "players": {},
            "versions": versions,
            "shownames": False,
            "showpersonalsort": True,
            "filterempty": True,
        },
        {
            "refresh": url_for("danevo_pages.listrecords", userid=userid),
            "player": url_for("danevo_pages.viewplayer", userid=-1),
            "individual_score": url_for("danevo_pages.viewtopscores", musicid=-1),
        },
    )


@danevo_pages.route("/records/<int:userid>/list")
@jsonify
@loginrequired
def listrecords(userid: UserID) -> Dict[str, Any]:
    frontend = DanceEvolutionFrontend(g.data, g.config, g.cache)
    return {
        "records": frontend.get_records(userid),
        "players": {},
    }


@danevo_pages.route("/topscores/<int:musicid>")
@loginrequired
def viewtopscores(musicid: int) -> Response:
    # We just want to find the latest mix that this song exists in
    frontend = DanceEvolutionFrontend(g.data, g.config, g.cache)
    versions = sorted(
        [version for (game, version, name) in frontend.all_games()],
        reverse=True,
    )
    name = None
    artist = None
    genre = None
    kcal = None
    levels = [0, 0, 0, 0, 0]

    for version in versions:
        for chart in [0, 1, 2, 3, 4]:
            details = g.data.local.music.get_song(GameConstants.DANCE_EVOLUTION, version, musicid, chart)
            if details is not None:
                if name is None:
                    name = details.name
                if artist is None:
                    artist = details.artist
                if genre is None:
                    genre = details.genre
                if kcal is None:
                    kcal = details.data.get_float("kcal")
                if levels[chart] == 0:
                    levels[chart] = details.data.get_int("level")

    if name is None or not [x for x in levels if x > 0]:
        # Not a real song!
        abort(404)

    top_scores = frontend.get_top_scores(musicid)

    return render_react(
        f"Top Dance Evolution Scores for {artist} - {name}",
        "danevo/topscores.react.js",
        {
            "name": name,
            "artist": artist,
            "genre": genre,
            "levels": levels,
            "kcal": kcal,
            "players": top_scores["players"],
            "topscores": top_scores["topscores"],
        },
        {
            "refresh": url_for("danevo_pages.listtopscores", musicid=musicid),
            "player": url_for("danevo_pages.viewplayer", userid=-1),
        },
    )


@danevo_pages.route("/topscores/<int:musicid>/list")
@jsonify
@loginrequired
def listtopscores(musicid: int) -> Dict[str, Any]:
    frontend = DanceEvolutionFrontend(g.data, g.config, g.cache)
    return frontend.get_top_scores(musicid)


@danevo_pages.route("/players")
@loginrequired
def viewplayers() -> Response:
    frontend = DanceEvolutionFrontend(g.data, g.config, g.cache)
    return render_react(
        "All Dance Evolution Players",
        "danevo/allplayers.react.js",
        {"players": frontend.get_all_players()},
        {
            "refresh": url_for("danevo_pages.listplayers"),
            "player": url_for("danevo_pages.viewplayer", userid=-1),
        },
    )


@danevo_pages.route("/players/list")
@jsonify
@loginrequired
def listplayers() -> Dict[str, Any]:
    frontend = DanceEvolutionFrontend(g.data, g.config, g.cache)
    return {
        "players": frontend.get_all_players(),
    }


@danevo_pages.route("/players/<int:userid>")
@loginrequired
def viewplayer(userid: UserID) -> Response:
    frontend = DanceEvolutionFrontend(g.data, g.config, g.cache)
    info = frontend.get_all_player_info([userid])[userid]
    if not info:
        abort(404)
    latest_version = sorted(info.keys(), reverse=True)[0]

    return render_react(
        f'{info[latest_version]["name"]}\'s Dance Evolution Profile',
        "danevo/player.react.js",
        {
            "playerid": userid,
            "own_profile": userid == g.userID,
            "player": info,
            "versions": {version: name for (game, version, name) in frontend.all_games()},
        },
        {
            "refresh": url_for("danevo_pages.listplayer", userid=userid),
            "records": url_for("danevo_pages.viewrecords", userid=userid),
        },
    )


@danevo_pages.route("/players/<int:userid>/list")
@jsonify
@loginrequired
def listplayer(userid: UserID) -> Dict[str, Any]:
    frontend = DanceEvolutionFrontend(g.data, g.config, g.cache)
    info = frontend.get_all_player_info([userid])[userid]

    return {
        "player": info,
    }


@danevo_pages.route("/options")
@loginrequired
def viewsettings() -> Response:
    frontend = DanceEvolutionFrontend(g.data, g.config, g.cache)
    userid = g.userID
    info = frontend.get_all_player_info([userid])[userid]
    if not info:
        abort(404)

    return render_react(
        "Dance Evolution Game Settings",
        "danevo/settings.react.js",
        {
            "player": info,
            "versions": {version: name for (game, version, name) in frontend.all_games()},
        },
        {
            "updatename": url_for("danevo_pages.updatename"),
        },
    )


@danevo_pages.route("/options/name/update", methods=["POST"])
@jsonify
@loginrequired
def updatename() -> Dict[str, Any]:
    version = int(request.get_json()["version"])
    name = request.get_json()["name"]
    user = g.data.local.user.get_user(g.userID)
    if user is None:
        raise Exception("Unable to find user to update!")

    # Grab profile and update name
    profile = g.data.local.user.get_profile(GameConstants.DANCE_EVOLUTION, version, user.id)
    if profile is None:
        raise Exception("Unable to find profile to update!")
    if len(name) == 0 or len(name) > 10:
        raise Exception("Invalid profile name!")
    if (
        re.match(
            "^["
            + "\uff20-\uff3a"
            + "\uff41-\uff5a"  # widetext A-Z and @
            + "\uff10-\uff19"  # widetext a-z
            + "\uff0c\uff0e\uff3f"  # widetext 0-9
            + "\u3041-\u308d\u308f\u3092\u3093"  # widetext ,._
            + "\u30a1-\u30ed\u30ef\u30f2\u30f3\u30fc"  # hiragana
            + "\u2605\u266a"  # allowed symbols
            + "]*$",  # katakana
            name,
        )
        is None
    ):
        raise Exception("Invalid profile name!")
    profile.replace_str("name", name)
    g.data.local.user.put_profile(GameConstants.DANCE_EVOLUTION, version, user.id, profile)

    # Return that we updated
    return {
        "version": version,
        "name": name,
    }


@danevo_pages.route("/dancemates/<int:userid>")
@loginrequired
def viewdancemates(userid: UserID) -> Response:
    frontend = DanceEvolutionFrontend(g.data, g.config, g.cache)
    info = frontend.get_latest_player_info([userid]).get(userid)
    if info is None:
        abort(404)

    # Since we have one version of DanEvo this is an ugly hack.
    dancemates_by_version, profiles = frontend.get_rivals(userid)
    dancemates = []
    for version, actual_dancemates in dancemates_by_version.items():
        dancemates.extend(actual_dancemates)

    return render_react(
        f'{info["name"]}\'s Dance Evolution Dance Mates',
        "danevo/dancemates.react.js",
        {
            "name": info["name"],
            "version": version,
            "dancemates": dancemates,
            "profiles": profiles,
        },
        {
            "refresh": url_for("danevo_pages.listdancemates", userid=userid),
        },
    )


@danevo_pages.route("/dancemates/<int:userid>/list")
@jsonify
@loginrequired
def listdancemates(userid: UserID) -> Dict[str, Any]:
    frontend = DanceEvolutionFrontend(g.data, g.config, g.cache)
    info = frontend.get_latest_player_info([userid]).get(userid)
    if info is None:
        abort(404)

    # Since we have one version of DanEvo this is an ugly hack.
    dancemates_by_version, profiles = frontend.get_rivals(userid)
    dancemates = []
    for version, actual_dancemates in dancemates_by_version.items():
        dancemates.extend(actual_dancemates)

    return {
        "name": info["name"],
        "version": version,
        "dancemates": dancemates,
        "profiles": profiles,
    }
