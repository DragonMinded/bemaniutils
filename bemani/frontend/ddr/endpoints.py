# vim: set fileencoding=utf-8
import re
from typing import Any, Dict, List, Optional
from flask import Blueprint, request, Response, url_for, abort

from bemani.common import ID, GameConstants
from bemani.data import Link, UserID
from bemani.frontend.app import loginrequired, jsonify, render_react
from bemani.frontend.ddr.ddr import DDRFrontend
from bemani.frontend.templates import templates_location
from bemani.frontend.static import static_location
from bemani.frontend.types import g


ddr_pages = Blueprint(
    "ddr_pages",
    __name__,
    url_prefix=f"/{GameConstants.DDR.value}",
    template_folder=templates_location,
    static_folder=static_location,
)


@ddr_pages.route("/scores")
@loginrequired
def viewnetworkscores() -> Response:
    # Only load the last 100 results for the initial fetch, so we can render faster
    frontend = DDRFrontend(g.data, g.config, g.cache)
    network_scores = frontend.get_network_scores(limit=100)
    if len(network_scores["attempts"]) > 10:
        network_scores["attempts"] = frontend.round_to_ten(network_scores["attempts"])

    return render_react(
        "Global DDR Scores",
        "ddr/scores.react.js",
        {
            "attempts": network_scores["attempts"],
            "songs": frontend.get_all_songs(),
            "players": network_scores["players"],
            "versions": {version: name for (game, version, name) in frontend.all_games()},
            "shownames": True,
            "shownewrecords": False,
        },
        {
            "refresh": url_for("ddr_pages.listnetworkscores"),
            "player": url_for("ddr_pages.viewplayer", userid=-1),
            "individual_score": url_for("ddr_pages.viewtopscores", musicid=-1),
        },
    )


@ddr_pages.route("/scores/list")
@jsonify
@loginrequired
def listnetworkscores() -> Dict[str, Any]:
    frontend = DDRFrontend(g.data, g.config, g.cache)
    return frontend.get_network_scores()


@ddr_pages.route("/scores/<int:userid>")
@loginrequired
def viewscores(userid: UserID) -> Response:
    frontend = DDRFrontend(g.data, g.config, g.cache)
    info = frontend.get_latest_player_info([userid]).get(userid)
    if info is None:
        abort(404)

    scores = frontend.get_scores(userid, limit=100)
    if len(scores) > 10:
        scores = frontend.round_to_ten(scores)

    return render_react(
        f'{info["name"]}\'s DDR Scores',
        "ddr/scores.react.js",
        {
            "attempts": scores,
            "songs": frontend.get_all_songs(),
            "players": {},
            "versions": {version: name for (game, version, name) in frontend.all_games()},
            "shownames": False,
            "shownewrecords": True,
        },
        {
            "refresh": url_for("ddr_pages.listscores", userid=userid),
            "player": url_for("ddr_pages.viewplayer", userid=-1),
            "individual_score": url_for("ddr_pages.viewtopscores", musicid=-1),
        },
    )


@ddr_pages.route("/scores/<int:userid>/list")
@jsonify
@loginrequired
def listscores(userid: UserID) -> Dict[str, Any]:
    frontend = DDRFrontend(g.data, g.config, g.cache)
    return {
        "attempts": frontend.get_scores(userid),
        "players": {},
    }


@ddr_pages.route("/records")
@loginrequired
def viewnetworkrecords() -> Response:
    frontend = DDRFrontend(g.data, g.config, g.cache)
    network_records = frontend.get_network_records()

    return render_react(
        "Global DDR Records",
        "ddr/records.react.js",
        {
            "records": network_records["records"],
            "songs": frontend.get_all_songs(),
            "players": network_records["players"],
            "versions": {version: name for (game, version, name) in frontend.all_games()},
            "shownames": True,
            "showpersonalsort": False,
            "filterempty": False,
        },
        {
            "refresh": url_for("ddr_pages.listnetworkrecords"),
            "player": url_for("ddr_pages.viewplayer", userid=-1),
            "individual_score": url_for("ddr_pages.viewtopscores", musicid=-1),
        },
    )


@ddr_pages.route("/records/list")
@jsonify
@loginrequired
def listnetworkrecords() -> Dict[str, Any]:
    frontend = DDRFrontend(g.data, g.config, g.cache)
    return frontend.get_network_records()


@ddr_pages.route("/records/<int:userid>")
@loginrequired
def viewrecords(userid: UserID) -> Response:
    frontend = DDRFrontend(g.data, g.config, g.cache)
    info = frontend.get_latest_player_info([userid]).get(userid)
    if info is None:
        abort(404)

    return render_react(
        f'{info["name"]}\'s DDR Records',
        "ddr/records.react.js",
        {
            "records": frontend.get_records(userid),
            "songs": frontend.get_all_songs(),
            "players": {},
            "versions": {version: name for (game, version, name) in frontend.all_games()},
            "shownames": False,
            "showpersonalsort": True,
            "filterempty": True,
        },
        {
            "refresh": url_for("ddr_pages.listrecords", userid=userid),
            "player": url_for("ddr_pages.viewplayer", userid=-1),
            "individual_score": url_for("ddr_pages.viewtopscores", musicid=-1),
        },
    )


@ddr_pages.route("/records/<int:userid>/list")
@jsonify
@loginrequired
def listrecords(userid: UserID) -> Dict[str, Any]:
    frontend = DDRFrontend(g.data, g.config, g.cache)
    return {
        "records": frontend.get_records(userid),
        "players": {},
    }


@ddr_pages.route("/topscores/<int:musicid>")
@loginrequired
def viewtopscores(musicid: int) -> Response:
    # We just want to find the latest mix that this song exists in
    frontend = DDRFrontend(g.data, g.config, g.cache)
    name = None
    artist = None
    genre = None
    difficulties: List[int] = [0] * 10
    groove: List[Dict[str, int]] = [{}] * 10

    for chart in frontend.valid_charts:
        details = g.data.local.music.get_song(GameConstants.DDR, 0, musicid, chart)
        if details is not None:
            name = details.name
            artist = details.artist
            genre = details.genre
            difficulties[chart] = details.data.get_int("difficulty", 13)
            groove[chart] = details.data.get_dict("groove")

    if name is None:
        # Not a real song!
        abort(404)

    top_scores = frontend.get_top_scores(musicid)

    return render_react(
        f"Top DDR Scores for {artist} - {name}",
        "ddr/topscores.react.js",
        {
            "name": name,
            "artist": artist,
            "genre": genre,
            "difficulties": difficulties,
            "groove": groove,
            "players": top_scores["players"],
            "topscores": top_scores["topscores"],
        },
        {
            "refresh": url_for("ddr_pages.listtopscores", musicid=musicid),
            "player": url_for("ddr_pages.viewplayer", userid=-1),
        },
    )


@ddr_pages.route("/topscores/<int:musicid>/list")
@jsonify
@loginrequired
def listtopscores(musicid: int) -> Dict[str, Any]:
    frontend = DDRFrontend(g.data, g.config, g.cache)
    return frontend.get_top_scores(musicid)


@ddr_pages.route("/players")
@loginrequired
def viewplayers() -> Response:
    frontend = DDRFrontend(g.data, g.config, g.cache)
    return render_react(
        "All DDR Players",
        "ddr/allplayers.react.js",
        {"players": frontend.get_all_players()},
        {
            "refresh": url_for("ddr_pages.listplayers"),
            "player": url_for("ddr_pages.viewplayer", userid=-1),
        },
    )


@ddr_pages.route("/players/list")
@jsonify
@loginrequired
def listplayers() -> Dict[str, Any]:
    frontend = DDRFrontend(g.data, g.config, g.cache)
    return {
        "players": frontend.get_all_players(),
    }


@ddr_pages.route("/players/<int:userid>")
@loginrequired
def viewplayer(userid: UserID) -> Response:
    frontend = DDRFrontend(g.data, g.config, g.cache)
    info = frontend.get_all_player_info([userid])[userid]
    if not info:
        abort(404)
    latest_version = sorted(info.keys(), reverse=True)[0]

    return render_react(
        f'{info[latest_version]["name"]}\'s DDR Profile',
        "ddr/player.react.js",
        {
            "playerid": userid,
            "own_profile": userid == g.userID,
            "player": info,
            "versions": {version: name for (game, version, name) in frontend.all_games()},
        },
        {
            "refresh": url_for("ddr_pages.listplayer", userid=userid),
            "records": url_for("ddr_pages.viewrecords", userid=userid),
            "scores": url_for("ddr_pages.viewscores", userid=userid),
        },
    )


@ddr_pages.route("/players/<int:userid>/list")
@jsonify
@loginrequired
def listplayer(userid: UserID) -> Dict[str, Any]:
    frontend = DDRFrontend(g.data, g.config, g.cache)
    info = frontend.get_all_player_info([userid])[userid]

    return {
        "player": info,
    }


@ddr_pages.route("/options")
@loginrequired
def viewsettings() -> Response:
    frontend = DDRFrontend(g.data, g.config, g.cache)
    userid = g.userID
    info = frontend.get_all_player_info([userid])[userid]
    if not info:
        abort(404)

    return render_react(
        "DDR Game Settings",
        "ddr/settings.react.js",
        {
            "player": info,
            "versions": {version: name for (game, version, name) in frontend.all_games()},
        },
        {
            "updatename": url_for("ddr_pages.updatename"),
            "updateweight": url_for("ddr_pages.updateweight"),
            "updateearlylate": url_for("ddr_pages.updateearlylate"),
            "updatebackgroundcombo": url_for("ddr_pages.updatebackgroundcombo"),
            "updatesettings": url_for("ddr_pages.updatesettings"),
        },
    )


@ddr_pages.route("/options/name/update", methods=["POST"])
@jsonify
@loginrequired
def updatename() -> Dict[str, Any]:
    frontend = DDRFrontend(g.data, g.config, g.cache)
    version = int(request.get_json()["version"])
    name = request.get_json()["name"]
    user = g.data.local.user.get_user(g.userID)
    if user is None:
        raise Exception("Unable to find user to update!")

    # Grab profile and update name
    profile = g.data.local.user.get_profile(GameConstants.DDR, version, user.id)
    if profile is None:
        raise Exception("Unable to find profile to update!")
    if len(name) == 0 or len(name) > 8:
        raise Exception("Invalid profile name!")
    if re.match(r"^[-&$\\.\\?!A-Z0-9 ]*$", name) is None:
        raise Exception("Invalid profile name!")
    profile = frontend.update_name(profile, name)
    g.data.local.user.put_profile(GameConstants.DDR, version, user.id, profile)

    # Return that we updated
    return {
        "version": version,
        "name": name,
    }


@ddr_pages.route("/options/weight/update", methods=["POST"])
@jsonify
@loginrequired
def updateweight() -> Dict[str, Any]:
    frontend = DDRFrontend(g.data, g.config, g.cache)
    version = int(request.get_json()["version"])
    weight = int(float(request.get_json()["weight"]) * 10)
    enabled = request.get_json()["enabled"]
    user = g.data.local.user.get_user(g.userID)
    if user is None:
        raise Exception("Unable to find user to update!")

    # Grab profile and update weight
    profile = g.data.local.user.get_profile(GameConstants.DDR, version, user.id)
    if profile is None:
        raise Exception("Unable to find profile to update!")
    if enabled:
        if weight <= 0 or weight > 9999:
            raise Exception("Invalid weight!")
    profile = frontend.update_weight(profile, weight, enabled)
    g.data.local.user.put_profile(GameConstants.DDR, version, user.id, profile)

    # Return that we updated
    return {
        "version": version,
        "weight": weight,
        "enabled": enabled,
    }


@ddr_pages.route("/options/earlylate/update", methods=["POST"])
@jsonify
@loginrequired
def updateearlylate() -> Dict[str, Any]:
    frontend = DDRFrontend(g.data, g.config, g.cache)
    version = int(request.get_json()["version"])
    value = request.get_json()["value"]
    user = g.data.local.user.get_user(g.userID)
    if user is None:
        raise Exception("Unable to find user to update!")

    # Grab profile and update early/late indicator
    profile = g.data.local.user.get_profile(GameConstants.DDR, version, user.id)
    if profile is None:
        raise Exception("Unable to find profile to update!")
    profile = frontend.update_early_late(profile, value)
    g.data.local.user.put_profile(GameConstants.DDR, version, user.id, profile)

    # Return that we updated
    return {
        "version": version,
        "value": value != 0,
    }


@ddr_pages.route("/options/backgroundcombo/update", methods=["POST"])
@jsonify
@loginrequired
def updatebackgroundcombo() -> Dict[str, Any]:
    frontend = DDRFrontend(g.data, g.config, g.cache)
    version = int(request.get_json()["version"])
    value = request.get_json()["value"]
    user = g.data.local.user.get_user(g.userID)
    if user is None:
        raise Exception("Unable to find user to update!")

    # Grab profile and update combo position
    profile = g.data.local.user.get_profile(GameConstants.DDR, version, user.id)
    if profile is None:
        raise Exception("Unable to find profile to update!")
    profile = frontend.update_background_combo(profile, value)
    g.data.local.user.put_profile(GameConstants.DDR, version, user.id, profile)

    # Return that we updated
    return {
        "version": version,
        "value": value != 0,
    }


@ddr_pages.route("/options/settings/update", methods=["POST"])
@jsonify
@loginrequired
def updatesettings() -> Dict[str, Any]:
    frontend = DDRFrontend(g.data, g.config, g.cache)
    settings = request.get_json()["settings"]
    version = int(request.get_json()["version"])
    user = g.data.local.user.get_user(g.userID)
    if user is None:
        raise Exception("Unable to find user to update!")

    # Grab profile and settings dict that needs updating
    profile = g.data.local.user.get_profile(GameConstants.DDR, version, user.id)
    if profile is None:
        raise Exception("Unable to find profile to update!")
    profile = frontend.update_settings(profile, settings)
    g.data.local.user.put_profile(GameConstants.DDR, version, user.id, profile)

    # Return updated settings
    info = frontend.get_all_player_info([user.id])[user.id]
    return {
        "player": info,
        "version": version,
    }


@ddr_pages.route("/rivals")
@loginrequired
def viewrivals() -> Response:
    frontend = DDRFrontend(g.data, g.config, g.cache)
    rivals, info = frontend.get_rivals(g.userID)

    return render_react(
        "DDR Rivals",
        "ddr/rivals.react.js",
        {
            "userid": str(g.userID),
            "rivals": rivals,
            "max_active_rivals": frontend.max_active_rivals,
            "players": info,
            "versions": {version: name for (game, version, name) in frontend.all_games()},
        },
        {
            "refresh": url_for("ddr_pages.listrivals"),
            "search": url_for("ddr_pages.searchrivals"),
            "player": url_for("ddr_pages.viewplayer", userid=-1),
            "addrival": url_for("ddr_pages.addrival"),
            "removerival": url_for("ddr_pages.removerival"),
            "setactiverival": url_for("ddr_pages.setactiverival"),
            "setinactiverival": url_for("ddr_pages.setinactiverival"),
        },
    )


@ddr_pages.route("/rivals/list")
@jsonify
@loginrequired
def listrivals() -> Dict[str, Any]:
    frontend = DDRFrontend(g.data, g.config, g.cache)
    rivals, info = frontend.get_rivals(g.userID)

    return {
        "rivals": rivals,
        "players": info,
    }


@ddr_pages.route("/rivals/search", methods=["POST"])
@jsonify
@loginrequired
def searchrivals() -> Dict[str, Any]:
    frontend = DDRFrontend(g.data, g.config, g.cache)
    version = int(request.get_json()["version"])
    name = request.get_json()["term"]

    # Try to treat the term as an extid
    extid = ID.parse_extid(name)

    matches = set()
    profiles = g.data.remote.user.get_all_profiles(GameConstants.DDR, version)
    for userid, profile in profiles:
        if profile.extid == extid or profile.get_str("name").lower() == name.lower():
            matches.add(userid)

    info = frontend.get_all_player_info(list(matches), allow_remote=True)
    return {
        "results": info,
    }


@ddr_pages.route("/rivals/add", methods=["POST"])
@jsonify
@loginrequired
def addrival() -> Dict[str, Any]:
    frontend = DDRFrontend(g.data, g.config, g.cache)
    version = int(request.get_json()["version"])
    other_userid = UserID(int(request.get_json()["userid"]))
    userid = g.userID

    # Find a slot to put the rival into
    occupied: List[Optional[Link]] = [None] * 10
    for link in g.data.local.user.get_links(GameConstants.DDR, version, userid):
        if link.type[:7] != "friend_":
            continue

        pos = int(link.type[7:])
        if pos >= 0 and pos < 10:
            occupied[pos] = link

    # Put rival in the first slot
    newrivalpos = -1
    for i in range(len(occupied)):
        if occupied[i] is None:
            newrivalpos = i
            break

    if newrivalpos == -1:
        raise Exception("No room for another rival!")

    # Add this rival link
    profile = g.data.remote.user.get_profile(GameConstants.DDR, version, other_userid)
    if profile is None:
        raise Exception("Unable to find profile for rival!")

    g.data.local.user.put_link(
        GameConstants.DDR,
        version,
        userid,
        f"friend_{newrivalpos}",
        other_userid,
        {},
    )

    # Now return updated rival info
    rivals, info = frontend.get_rivals(userid)

    return {
        "rivals": rivals,
        "players": info,
    }


@ddr_pages.route("/rivals/remove", methods=["POST"])
@jsonify
@loginrequired
def removerival() -> Dict[str, Any]:
    frontend = DDRFrontend(g.data, g.config, g.cache)
    version = int(request.get_json()["version"])
    other_userid = UserID(int(request.get_json()["userid"]))
    position = int(request.get_json()["position"])
    userid = g.userID

    # Remove this rival link
    g.data.local.user.destroy_link(
        GameConstants.DDR,
        version,
        userid,
        f"friend_{position}",
        other_userid,
    )

    profile = g.data.local.user.get_profile(GameConstants.DDR, version, userid)
    if profile is None:
        raise Exception("Unable to find profile to update!")
    profile = frontend.deactivate_rival(profile, position)
    g.data.local.user.put_profile(GameConstants.DDR, version, userid, profile)

    # Now return updated rival info
    rivals, info = frontend.get_rivals(userid)

    return {
        "rivals": rivals,
        "players": info,
    }


@ddr_pages.route("/rivals/activate", methods=["POST"])
@jsonify
@loginrequired
def setactiverival() -> Dict[str, Any]:
    frontend = DDRFrontend(g.data, g.config, g.cache)
    version = int(request.get_json()["version"])
    position = int(request.get_json()["position"])
    userid = g.userID

    profile = g.data.local.user.get_profile(GameConstants.DDR, version, userid)
    if profile is None:
        raise Exception("Unable to find profile to update!")
    profile = frontend.activate_rival(profile, position)
    g.data.local.user.put_profile(GameConstants.DDR, version, userid, profile)

    # Now return updated rival info
    rivals, info = frontend.get_rivals(userid)

    return {
        "rivals": rivals,
        "players": info,
    }


@ddr_pages.route("/rivals/inactivate", methods=["POST"])
@jsonify
@loginrequired
def setinactiverival() -> Dict[str, Any]:
    frontend = DDRFrontend(g.data, g.config, g.cache)
    version = int(request.get_json()["version"])
    position = int(request.get_json()["position"])
    userid = g.userID

    profile = g.data.local.user.get_profile(GameConstants.DDR, version, userid)
    if profile is None:
        raise Exception("Unable to find profile to update!")
    profile = frontend.deactivate_rival(profile, position)
    g.data.local.user.put_profile(GameConstants.DDR, version, userid, profile)

    # Now return updated rival info
    rivals, info = frontend.get_rivals(userid)

    return {
        "rivals": rivals,
        "players": info,
    }
