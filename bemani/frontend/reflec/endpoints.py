# vim: set fileencoding=utf-8
import re
from typing import Any, Dict, List
from typing_extensions import Final
from flask import Blueprint, request, Response, url_for, abort

from bemani.common import ID, GameConstants
from bemani.data import UserID
from bemani.frontend.app import loginrequired, jsonify, render_react
from bemani.frontend.reflec.reflec import ReflecBeatFrontend
from bemani.frontend.templates import templates_location
from bemani.frontend.static import static_location
from bemani.frontend.types import g


reflec_pages = Blueprint(
    "reflec_pages",
    __name__,
    url_prefix=f"/{GameConstants.REFLEC_BEAT.value}",
    template_folder=templates_location,
    static_folder=static_location,
)

NO_RIVAL_SUPPORT: Final[List[int]] = [1]


@reflec_pages.route("/scores")
@loginrequired
def viewnetworkscores() -> Response:
    # Only load the last 100 results for the initial fetch, so we can render faster
    frontend = ReflecBeatFrontend(g.data, g.config, g.cache)
    network_scores = frontend.get_network_scores(limit=100)
    if len(network_scores["attempts"]) > 10:
        network_scores["attempts"] = frontend.round_to_ten(network_scores["attempts"])

    return render_react(
        "Global Reflec Beat Scores",
        "reflec/scores.react.js",
        {
            "attempts": network_scores["attempts"],
            "songs": frontend.get_all_songs(),
            "players": network_scores["players"],
            "shownames": True,
            "shownewrecords": False,
        },
        {
            "refresh": url_for("reflec_pages.listnetworkscores"),
            "player": url_for("reflec_pages.viewplayer", userid=-1),
            "individual_score": url_for("reflec_pages.viewtopscores", musicid=-1),
        },
    )


@reflec_pages.route("/scores/list")
@jsonify
@loginrequired
def listnetworkscores() -> Dict[str, Any]:
    frontend = ReflecBeatFrontend(g.data, g.config, g.cache)
    return frontend.get_network_scores()


@reflec_pages.route("/scores/<int:userid>")
@loginrequired
def viewscores(userid: UserID) -> Response:
    frontend = ReflecBeatFrontend(g.data, g.config, g.cache)
    info = frontend.get_latest_player_info([userid]).get(userid)
    if info is None:
        abort(404)

    scores = frontend.get_scores(userid, limit=100)
    if len(scores) > 10:
        scores = frontend.round_to_ten(scores)

    return render_react(
        f'{info["name"]}\'s Reflec Beat Scores',
        "reflec/scores.react.js",
        {
            "attempts": scores,
            "songs": frontend.get_all_songs(),
            "players": {},
            "shownames": False,
            "shownewrecords": True,
        },
        {
            "refresh": url_for("reflec_pages.listscores", userid=userid),
            "player": url_for("reflec_pages.viewplayer", userid=-1),
            "individual_score": url_for("reflec_pages.viewtopscores", musicid=-1),
        },
    )


@reflec_pages.route("/scores/<int:userid>/list")
@jsonify
@loginrequired
def listscores(userid: UserID) -> Dict[str, Any]:
    frontend = ReflecBeatFrontend(g.data, g.config, g.cache)
    return {
        "attempts": frontend.get_scores(userid),
        "players": {},
    }


@reflec_pages.route("/records")
@loginrequired
def viewnetworkrecords() -> Response:
    frontend = ReflecBeatFrontend(g.data, g.config, g.cache)
    network_records = frontend.get_network_records()
    versions = {version: name for (game, version, name) in frontend.all_games()}
    versions[0] = "CS and Licenses"

    return render_react(
        "Global Reflec Beat Records",
        "reflec/records.react.js",
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
            "refresh": url_for("reflec_pages.listnetworkrecords"),
            "player": url_for("reflec_pages.viewplayer", userid=-1),
            "individual_score": url_for("reflec_pages.viewtopscores", musicid=-1),
        },
    )


@reflec_pages.route("/records/list")
@jsonify
@loginrequired
def listnetworkrecords() -> Dict[str, Any]:
    frontend = ReflecBeatFrontend(g.data, g.config, g.cache)
    return frontend.get_network_records()


@reflec_pages.route("/records/<int:userid>")
@loginrequired
def viewrecords(userid: UserID) -> Response:
    frontend = ReflecBeatFrontend(g.data, g.config, g.cache)
    info = frontend.get_latest_player_info([userid]).get(userid)
    if info is None:
        abort(404)
    versions = {version: name for (game, version, name) in frontend.all_games()}

    return render_react(
        f'{info["name"]}\'s Reflec Beat Records',
        "reflec/records.react.js",
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
            "refresh": url_for("reflec_pages.listrecords", userid=userid),
            "player": url_for("reflec_pages.viewplayer", userid=-1),
            "individual_score": url_for("reflec_pages.viewtopscores", musicid=-1),
        },
    )


@reflec_pages.route("/records/<int:userid>/list")
@jsonify
@loginrequired
def listrecords(userid: UserID) -> Dict[str, Any]:
    frontend = ReflecBeatFrontend(g.data, g.config, g.cache)
    return {
        "records": frontend.get_records(userid),
        "players": {},
    }


@reflec_pages.route("/topscores/<int:musicid>")
@loginrequired
def viewtopscores(musicid: int) -> Response:
    # We just want to find the latest mix that this song exists in
    frontend = ReflecBeatFrontend(g.data, g.config, g.cache)
    name = None
    artist = None
    difficulties = [0, 0, 0, 0]

    for chart in [0, 1, 2, 3]:
        details = g.data.local.music.get_song(
            GameConstants.REFLEC_BEAT, 0, musicid, chart
        )
        if details is not None:
            if name is None:
                name = details.name
            if artist is None:
                artist = details.artist
            if difficulties[chart] == 0:
                difficulties[chart] = details.data.get_int("difficulty")

    if name is None:
        # Not a real song!
        abort(404)

    top_scores = frontend.get_top_scores(musicid)

    return render_react(
        f"Top Reflec Beat Scores for {artist} - {name}",
        "reflec/topscores.react.js",
        {
            "name": name,
            "artist": artist,
            "difficulties": difficulties,
            "players": top_scores["players"],
            "topscores": top_scores["topscores"],
        },
        {
            "refresh": url_for("reflec_pages.listtopscores", musicid=musicid),
            "player": url_for("reflec_pages.viewplayer", userid=-1),
        },
    )


@reflec_pages.route("/topscores/<int:musicid>/list")
@jsonify
@loginrequired
def listtopscores(musicid: int) -> Dict[str, Any]:
    frontend = ReflecBeatFrontend(g.data, g.config, g.cache)
    return frontend.get_top_scores(musicid)


@reflec_pages.route("/players")
@loginrequired
def viewplayers() -> Response:
    frontend = ReflecBeatFrontend(g.data, g.config, g.cache)
    return render_react(
        "All Reflec Beat Players",
        "reflec/allplayers.react.js",
        {"players": frontend.get_all_players()},
        {
            "refresh": url_for("reflec_pages.listplayers"),
            "player": url_for("reflec_pages.viewplayer", userid=-1),
        },
    )


@reflec_pages.route("/players/list")
@jsonify
@loginrequired
def listplayers() -> Dict[str, Any]:
    frontend = ReflecBeatFrontend(g.data, g.config, g.cache)
    return {
        "players": frontend.get_all_players(),
    }


@reflec_pages.route("/players/<int:userid>")
@loginrequired
def viewplayer(userid: UserID) -> Response:
    frontend = ReflecBeatFrontend(g.data, g.config, g.cache)
    info = frontend.get_all_player_info([userid])[userid]
    if not info:
        abort(404)
    latest_version = sorted(info.keys(), reverse=True)[0]

    return render_react(
        f'{info[latest_version]["name"]}\'s Reflec Beat Profile',
        "reflec/player.react.js",
        {
            "playerid": userid,
            "own_profile": userid == g.userID,
            "player": info,
            "versions": {
                version: name for (game, version, name) in frontend.all_games()
            },
        },
        {
            "refresh": url_for("reflec_pages.listplayer", userid=userid),
            "records": url_for("reflec_pages.viewrecords", userid=userid),
            "scores": url_for("reflec_pages.viewscores", userid=userid),
        },
    )


@reflec_pages.route("/players/<int:userid>/list")
@jsonify
@loginrequired
def listplayer(userid: UserID) -> Dict[str, Any]:
    frontend = ReflecBeatFrontend(g.data, g.config, g.cache)
    info = frontend.get_all_player_info([userid])[userid]

    return {
        "player": info,
    }


@reflec_pages.route("/options")
@loginrequired
def viewsettings() -> Response:
    frontend = ReflecBeatFrontend(g.data, g.config, g.cache)
    userid = g.userID
    info = frontend.get_all_player_info([userid])[userid]
    if not info:
        abort(404)

    return render_react(
        "Reflec Beat Game Settings",
        "reflec/settings.react.js",
        {
            "player": info,
            "versions": {
                version: name for (game, version, name) in frontend.all_games()
            },
        },
        {
            "updatename": url_for("reflec_pages.updatename"),
        },
    )


@reflec_pages.route("/options/name/update", methods=["POST"])
@jsonify
@loginrequired
def updatename() -> Dict[str, Any]:
    version = int(request.get_json()["version"])
    name = request.get_json()["name"]
    user = g.data.local.user.get_user(g.userID)
    if user is None:
        raise Exception("Unable to find user to update!")

    # Grab profile and update name
    profile = g.data.local.user.get_profile(GameConstants.REFLEC_BEAT, version, user.id)
    if profile is None:
        raise Exception("Unable to find profile to update!")
    if len(name) == 0 or len(name) > 8:
        raise Exception("Invalid profile name!")
    if version <= 3:
        # Older reflec didn't allow for lowercase
        if (
            re.match(
                "^["
                + "\uFF21-\uFF3A"
                + "\uFF10-\uFF19"  # widetext A-Z
                + "\uFF0E\u2212\uFF3F\u30FB"  # widetext 0-9
                + "\uFF06\uFF01\uFF1F\uFF0F"
                + "\uFF0A\uFF03\u266D\u2605"
                + "\uFF20\u266A\u2193\u2191"
                + "\u2192\u2190\uFF08\uFF09"
                + "\u221E\u25C6\u25CF\u25BC"
                + "\uFFE5\uFF3E\u2200\uFF05"
                + "\u3000"
                + "]*$",  # widetext space
                name,
            )
            is None
        ):
            raise Exception("Invalid profile name!")
    else:
        # Newer reflec allows the same as older but
        # also allows for lowercase widetext.
        if (
            re.match(
                "^["
                + "\uFF21-\uFF3A"
                + "\uFF41-\uFF5A"  # widetext A-Z
                + "\uFF10-\uFF19"  # widetext a-z
                + "\uFF0E\u2212\uFF3F\u30FB"  # widetext 0-9
                + "\uFF06\uFF01\uFF1F\uFF0F"
                + "\uFF0A\uFF03\u266D\u2605"
                + "\uFF20\u266A\u2193\u2191"
                + "\u2192\u2190\uFF08\uFF09"
                + "\u221E\u25C6\u25CF\u25BC"
                + "\uFFE5\uFF3E\u2200\uFF05"
                + "\u3000"
                + "]*$",  # widetext space
                name,
            )
            is None
        ):
            raise Exception("Invalid profile name!")
    profile.replace_str("name", name)
    g.data.local.user.put_profile(GameConstants.REFLEC_BEAT, version, user.id, profile)

    # Return that we updated
    return {
        "version": version,
        "name": name,
    }


@reflec_pages.route("/rivals")
@loginrequired
def viewrivals() -> Response:
    frontend = ReflecBeatFrontend(g.data, g.config, g.cache)
    rivals, playerinfo = frontend.get_rivals(g.userID)

    # Reflec Beat 1 has no rivals support
    for no_rivals_support in NO_RIVAL_SUPPORT:
        if no_rivals_support in rivals:
            del rivals[no_rivals_support]

    return render_react(
        "Reflec Beat Rivals",
        "reflec/rivals.react.js",
        {
            "userid": str(g.userID),
            "rivals": rivals,
            "players": playerinfo,
            "versions": {
                version: name
                for (game, version, name) in frontend.all_games()
                if version not in NO_RIVAL_SUPPORT
            },
        },
        {
            "refresh": url_for("reflec_pages.listrivals"),
            "search": url_for("reflec_pages.searchrivals"),
            "player": url_for("reflec_pages.viewplayer", userid=-1),
            "addrival": url_for("reflec_pages.addrival"),
            "removerival": url_for("reflec_pages.removerival"),
        },
    )


@reflec_pages.route("/rivals/list")
@jsonify
@loginrequired
def listrivals() -> Dict[str, Any]:
    frontend = ReflecBeatFrontend(g.data, g.config, g.cache)
    rivals, playerinfo = frontend.get_rivals(g.userID)

    # Reflec Beat 1 has no rivals support
    for no_rivals_support in NO_RIVAL_SUPPORT:
        if no_rivals_support in rivals:
            del rivals[no_rivals_support]

    return {
        "rivals": rivals,
        "players": playerinfo,
    }


@reflec_pages.route("/rivals/search", methods=["POST"])
@jsonify
@loginrequired
def searchrivals() -> Dict[str, Any]:
    frontend = ReflecBeatFrontend(g.data, g.config, g.cache)
    version = int(request.get_json()["version"])
    name = request.get_json()["term"]

    # Try to treat the term as an extid
    extid = ID.parse_extid(name)

    matches = set()
    profiles = g.data.remote.user.get_all_profiles(GameConstants.REFLEC_BEAT, version)
    for userid, profile in profiles:
        if profile.extid == extid or profile.get_str("name").lower() == name.lower():
            matches.add(userid)

    playerinfo = frontend.get_all_player_info(list(matches), allow_remote=True)
    return {
        "results": playerinfo,
    }


@reflec_pages.route("/rivals/add", methods=["POST"])
@jsonify
@loginrequired
def addrival() -> Dict[str, Any]:
    frontend = ReflecBeatFrontend(g.data, g.config, g.cache)
    version = int(request.get_json()["version"])
    other_userid = UserID(int(request.get_json()["userid"]))
    userid = g.userID

    # Add this rival link
    profile = g.data.remote.user.get_profile(
        GameConstants.REFLEC_BEAT, version, other_userid
    )
    if profile is None:
        raise Exception("Unable to find profile for rival!")

    g.data.local.user.put_link(
        GameConstants.REFLEC_BEAT,
        version,
        userid,
        "rival",
        other_userid,
        {},
    )

    # Now return updated rival info
    rivals, playerinfo = frontend.get_rivals(userid)

    return {
        "rivals": rivals,
        "players": playerinfo,
    }


@reflec_pages.route("/rivals/remove", methods=["POST"])
@jsonify
@loginrequired
def removerival() -> Dict[str, Any]:
    frontend = ReflecBeatFrontend(g.data, g.config, g.cache)
    version = int(request.get_json()["version"])
    other_userid = UserID(int(request.get_json()["userid"]))
    userid = g.userID

    # Remove this rival link
    g.data.local.user.destroy_link(
        GameConstants.REFLEC_BEAT,
        version,
        userid,
        "rival",
        other_userid,
    )

    # Now return updated rival info
    rivals, playerinfo = frontend.get_rivals(userid)

    return {
        "rivals": rivals,
        "players": playerinfo,
    }
