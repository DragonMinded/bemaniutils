# vim: set fileencoding=utf-8
import re
from typing import Any, Dict
from flask import Blueprint, request, Response, url_for, abort

from bemani.common import ID, GameConstants, RegionConstants, DBConstants
from bemani.data import UserID
from bemani.frontend.app import loginrequired, jsonify, render_react
from bemani.frontend.iidx.iidx import IIDXFrontend
from bemani.frontend.templates import templates_location
from bemani.frontend.static import static_location
from bemani.frontend.types import g

iidx_pages = Blueprint(
    "iidx_pages",
    __name__,
    url_prefix=f"/{GameConstants.IIDX.value}",
    template_folder=templates_location,
    static_folder=static_location,
)


@iidx_pages.route("/scores")
@loginrequired
def viewnetworkscores() -> Response:
    # Only load the last 100 results for the initial fetch, so we can render faster
    frontend = IIDXFrontend(g.data, g.config, g.cache)
    network_scores = frontend.get_network_scores(limit=100)
    if len(network_scores["attempts"]) > 10:
        network_scores["attempts"] = frontend.round_to_ten(network_scores["attempts"])

    return render_react(
        "Global IIDX Scores",
        "iidx/scores.react.js",
        {
            "attempts": network_scores["attempts"],
            "songs": frontend.get_all_songs(),
            "players": network_scores["players"],
            "versions": {
                version: name for (game, version, name) in frontend.all_games()
            },
            "showdjnames": True,
            "shownewrecords": False,
        },
        {
            "refresh": url_for("iidx_pages.listnetworkscores"),
            "player": url_for("iidx_pages.viewplayer", userid=-1),
            "individual_score": url_for("iidx_pages.viewtopscores", musicid=-1),
        },
    )


@iidx_pages.route("/scores/list")
@jsonify
@loginrequired
def listnetworkscores() -> Dict[str, Any]:
    frontend = IIDXFrontend(g.data, g.config, g.cache)
    return frontend.get_network_scores()


@iidx_pages.route("/scores/<int:userid>")
@loginrequired
def viewscores(userid: UserID) -> Response:
    frontend = IIDXFrontend(g.data, g.config, g.cache)
    djinfo = frontend.get_latest_player_info([userid]).get(userid)
    if djinfo is None:
        abort(404)

    scores = frontend.get_scores(userid, limit=100)
    if len(scores) > 10:
        scores = frontend.round_to_ten(scores)

    return render_react(
        f'dj {djinfo["name"]}\'s IIDX Scores',
        "iidx/scores.react.js",
        {
            "attempts": scores,
            "songs": frontend.get_all_songs(),
            "players": {},
            "versions": {
                version: name for (game, version, name) in frontend.all_games()
            },
            "showdjnames": False,
            "shownewrecords": True,
        },
        {
            "refresh": url_for("iidx_pages.listscores", userid=userid),
            "player": url_for("iidx_pages.viewplayer", userid=-1),
            "individual_score": url_for("iidx_pages.viewtopscores", musicid=-1),
        },
    )


@iidx_pages.route("/scores/<int:userid>/list")
@jsonify
@loginrequired
def listscores(userid: UserID) -> Dict[str, Any]:
    frontend = IIDXFrontend(g.data, g.config, g.cache)
    return {
        "attempts": frontend.get_scores(userid),
        "players": {},
    }


@iidx_pages.route("/records")
@loginrequired
def viewnetworkrecords() -> Response:
    frontend = IIDXFrontend(g.data, g.config, g.cache)
    network_records = frontend.get_network_records()

    return render_react(
        "Global IIDX Records",
        "iidx/records.react.js",
        {
            "records": network_records["records"],
            "songs": frontend.get_all_songs(),
            "players": network_records["players"],
            "versions": {
                version: name for (game, version, name) in frontend.all_games()
            },
            "showdjnames": True,
            "showpersonalsort": False,
            "filterempty": False,
        },
        {
            "refresh": url_for("iidx_pages.listnetworkrecords"),
            "player": url_for("iidx_pages.viewplayer", userid=-1),
            "individual_score": url_for("iidx_pages.viewtopscores", musicid=-1),
        },
    )


@iidx_pages.route("/records/list")
@jsonify
@loginrequired
def listnetworkrecords() -> Dict[str, Any]:
    frontend = IIDXFrontend(g.data, g.config, g.cache)
    return frontend.get_network_records()


@iidx_pages.route("/records/<int:userid>")
@loginrequired
def viewrecords(userid: UserID) -> Response:
    frontend = IIDXFrontend(g.data, g.config, g.cache)
    djinfo = frontend.get_latest_player_info([userid]).get(userid)
    if djinfo is None:
        abort(404)

    return render_react(
        f'dj {djinfo["name"]}\'s IIDX Records',
        "iidx/records.react.js",
        {
            "records": frontend.get_records(userid),
            "songs": frontend.get_all_songs(),
            "players": {},
            "versions": {
                version: name for (game, version, name) in frontend.all_games()
            },
            "showdjnames": False,
            "showpersonalsort": True,
            "filterempty": True,
        },
        {
            "refresh": url_for("iidx_pages.listrecords", userid=userid),
            "player": url_for("iidx_pages.viewplayer", userid=-1),
            "individual_score": url_for("iidx_pages.viewtopscores", musicid=-1),
        },
    )


@iidx_pages.route("/records/<int:userid>/list")
@jsonify
@loginrequired
def listrecords(userid: UserID) -> Dict[str, Any]:
    frontend = IIDXFrontend(g.data, g.config, g.cache)
    return {
        "records": frontend.get_records(userid),
        "players": {},
    }


@iidx_pages.route("/topscores/<int:musicid>")
@loginrequired
def viewtopscores(musicid: int) -> Response:
    # We just want to find the latest mix that this song exists in
    frontend = IIDXFrontend(g.data, g.config, g.cache)
    versions = sorted(
        [version for (game, version, name) in frontend.all_games()],
        reverse=True,
    )
    name = None
    artist = None
    genre = None
    difficulties = [0, 0, 0, 0, 0, 0]
    notecounts = [0, 0, 0, 0, 0, 0]

    for version in versions:
        for omniadd in [0, DBConstants.OMNIMIX_VERSION_BUMP]:
            for chart in [0, 1, 2, 3, 4, 5]:
                details = g.data.local.music.get_song(
                    GameConstants.IIDX, version + omniadd, musicid, chart
                )
                if details is not None:
                    name = details.name
                    artist = details.artist
                    genre = details.genre
                    difficulties[chart] = details.data.get_int("difficulty", 13)
                    notecounts[chart] = details.data.get_int("notecount", 5730)

    if name is None:
        # Not a real song!
        abort(404)

    top_scores = frontend.get_top_scores(musicid)

    return render_react(
        f"Top IIDX Scores for {artist} - {name}",
        "iidx/topscores.react.js",
        {
            "name": name,
            "artist": artist,
            "genre": genre,
            "difficulties": difficulties,
            "notecounts": notecounts,
            "players": top_scores["players"],
            "topscores": top_scores["topscores"],
        },
        {
            "refresh": url_for("iidx_pages.listtopscores", musicid=musicid),
            "player": url_for("iidx_pages.viewplayer", userid=-1),
        },
    )


@iidx_pages.route("/topscores/<int:musicid>/list")
@jsonify
@loginrequired
def listtopscores(musicid: int) -> Dict[str, Any]:
    frontend = IIDXFrontend(g.data, g.config, g.cache)
    return frontend.get_top_scores(musicid)


@iidx_pages.route("/players")
@loginrequired
def viewplayers() -> Response:
    frontend = IIDXFrontend(g.data, g.config, g.cache)
    return render_react(
        "All IIDX Players",
        "iidx/allplayers.react.js",
        {"players": frontend.get_all_players()},
        {
            "refresh": url_for("iidx_pages.listplayers"),
            "player": url_for("iidx_pages.viewplayer", userid=-1),
        },
    )


@iidx_pages.route("/players/list")
@jsonify
@loginrequired
def listplayers() -> Dict[str, Any]:
    frontend = IIDXFrontend(g.data, g.config, g.cache)
    return {
        "players": frontend.get_all_players(),
    }


@iidx_pages.route("/players/<int:userid>")
@loginrequired
def viewplayer(userid: UserID) -> Response:
    frontend = IIDXFrontend(g.data, g.config, g.cache)
    djinfo = frontend.get_all_player_info([userid])[userid]
    if not djinfo:
        abort(404)
    latest_version = sorted(djinfo.keys(), reverse=True)[0]

    for version in djinfo:
        sp_rival = g.data.local.user.get_link(
            GameConstants.IIDX, version, g.userID, "sp_rival", userid
        )
        dp_rival = g.data.local.user.get_link(
            GameConstants.IIDX, version, g.userID, "dp_rival", userid
        )
        djinfo[version]["sp_rival"] = sp_rival is not None
        djinfo[version]["dp_rival"] = dp_rival is not None

    return render_react(
        f'dj {djinfo[latest_version]["name"]}\'s IIDX Profile',
        "iidx/player.react.js",
        {
            "playerid": userid,
            "own_profile": userid == g.userID,
            "player": djinfo,
            "versions": {
                version: name for (game, version, name) in frontend.all_games()
            },
        },
        {
            "refresh": url_for("iidx_pages.listplayer", userid=userid),
            "records": url_for("iidx_pages.viewrecords", userid=userid),
            "scores": url_for("iidx_pages.viewscores", userid=userid),
            "addrival": url_for("iidx_pages.addrival"),
            "removerival": url_for("iidx_pages.removerival"),
        },
    )


@iidx_pages.route("/players/<int:userid>/list")
@jsonify
@loginrequired
def listplayer(userid: UserID) -> Dict[str, Any]:
    frontend = IIDXFrontend(g.data, g.config, g.cache)
    djinfo = frontend.get_all_player_info([userid])[userid]

    for version in djinfo:
        sp_rival = g.data.local.user.get_link(
            GameConstants.IIDX, version, g.userID, "sp_rival", userid
        )
        dp_rival = g.data.local.user.get_link(
            GameConstants.IIDX, version, g.userID, "dp_rival", userid
        )
        djinfo[version]["sp_rival"] = sp_rival is not None
        djinfo[version]["dp_rival"] = dp_rival is not None

    return {
        "player": djinfo,
    }


@iidx_pages.route("/options")
@loginrequired
def viewsettings() -> Response:
    frontend = IIDXFrontend(g.data, g.config, g.cache)
    userid = g.userID
    djinfo = frontend.get_all_player_info([userid])[userid]
    if not djinfo:
        abort(404)
    versions = sorted(
        [version for (game, version, name) in frontend.all_games()],
        reverse=True,
    )
    return render_react(
        "IIDX Game Settings",
        "iidx/settings.react.js",
        {
            "player": djinfo,
            "regions": RegionConstants.LUT,
            "versions": {
                version: name for (game, version, name) in frontend.all_games()
            },
            "qpros": frontend.get_all_items(versions),
        },
        {
            "updateqpro": url_for("iidx_pages.updateqpro"),
            "updateflags": url_for("iidx_pages.updateflags"),
            "updatesettings": url_for("iidx_pages.updatesettings"),
            "updatename": url_for("iidx_pages.updatename"),
            "updateprefecture": url_for("iidx_pages.updateprefecture"),
            "leavearcade": url_for("iidx_pages.leavearcade"),
        },
    )


@iidx_pages.route("/options/flags/update", methods=["POST"])
@jsonify
@loginrequired
def updateflags() -> Dict[str, Any]:
    frontend = IIDXFrontend(g.data, g.config, g.cache)
    flags = request.get_json()["flags"]
    version = int(request.get_json()["version"])
    user = g.data.local.user.get_user(g.userID)
    if user is None:
        raise Exception("Unable to find user to update!")

    # Grab profile and settings dict that needs updating
    profile = g.data.local.user.get_profile(GameConstants.IIDX, version, user.id)
    if profile is None:
        raise Exception("Unable to find profile to update!")
    settings_dict = profile.get_dict("settings")

    # Set bits for flags based on frontend
    flagint = 0
    flagint += 0x001 if flags["grade"] else 0
    flagint += 0x002 if flags["status"] else 0
    flagint += 0x004 if flags["difficulty"] else 0
    flagint += 0x008 if flags["alphabet"] else 0
    flagint += 0x010 if flags["rival_played"] else 0
    flagint += 0x040 if flags["rival_win_lose"] else 0
    flagint += 0x080 if flags["rival_info"] else 0
    flagint += 0x100 if flags["hide_play_count"] else 0
    flagint += 0x200 if flags["disable_graph_cutin"] else 0
    flagint += 0x400 if flags["classic_hispeed"] else 0
    flagint += 0x1000 if flags["hide_iidx_id"] else 0
    settings_dict.replace_int("flags", flagint)

    # Update special case flags
    settings_dict.replace_int(
        "disable_song_preview", 1 if flags["disable_song_preview"] else 0
    )
    settings_dict.replace_int("effector_lock", 1 if flags["effector_lock"] else 0)
    settings_dict.replace_int(
        "disable_hcn_color", 1 if flags["disable_hcn_color"] else 0
    )

    # Update the settings dict
    profile.replace_dict("settings", settings_dict)
    g.data.local.user.put_profile(GameConstants.IIDX, version, user.id, profile)

    # Return updated flags
    return {
        "flags": frontend.format_flags(settings_dict),
        "version": version,
    }


@iidx_pages.route("/options/qpro/update", methods=["POST"])
@jsonify
@loginrequired
def updateqpro() -> Dict[str, Any]:
    frontend = IIDXFrontend(g.data, g.config, g.cache)
    qpros = request.get_json()["qpro"]
    version = int(request.get_json()["version"])
    user = g.data.local.user.get_user(g.userID)
    if user is None:
        raise Exception("Unable to find user to update!")

    # Grab profile and qpro dict that needs updating
    profile = g.data.local.user.get_profile(GameConstants.IIDX, version, user.id)
    if profile is None:
        raise Exception("Unable to find profile to update!")
    qpro_dict = profile.get_dict("qpro")

    for qpro in qpros:
        qpro_dict.replace_int(qpro, qpros[qpro])

    # Update the qpro dict
    profile.replace_dict("qpro", qpro_dict)
    g.data.local.user.put_profile(GameConstants.IIDX, version, user.id, profile)

    # Return updated qpro
    return {
        "qpro": frontend.format_qpro(qpro_dict),
        "version": version,
    }


@iidx_pages.route("/options/settings/update", methods=["POST"])
@jsonify
@loginrequired
def updatesettings() -> Dict[str, Any]:
    frontend = IIDXFrontend(g.data, g.config, g.cache)
    settings = request.get_json()["settings"]
    version = int(request.get_json()["version"])
    user = g.data.local.user.get_user(g.userID)
    if user is None:
        raise Exception("Unable to find user to update!")

    # Grab profile and settings dict that needs updating
    profile = g.data.local.user.get_profile(GameConstants.IIDX, version, user.id)
    if profile is None:
        raise Exception("Unable to find profile to update!")
    settings_dict = profile.get_dict("settings")

    for setting in settings:
        settings_dict.replace_int(setting, settings[setting])

    # Update the settings dict
    profile.replace_dict("settings", settings_dict)
    g.data.local.user.put_profile(GameConstants.IIDX, version, user.id, profile)

    # Return updated settings
    return {
        "settings": frontend.format_settings(settings_dict),
        "version": version,
    }


@iidx_pages.route("/options/arcade/leave", methods=["POST"])
@jsonify
@loginrequired
def leavearcade() -> Dict[str, Any]:
    version = int(request.get_json()["version"])
    user = g.data.local.user.get_user(g.userID)
    if user is None:
        raise Exception("Unable to find user to update!")

    # Grab profile and nuke the shop location
    profile = g.data.local.user.get_profile(GameConstants.IIDX, version, user.id)
    if profile is None:
        raise Exception("Unable to find profile to update!")
    if "shop_location" in profile:
        del profile["shop_location"]
    g.data.local.user.put_profile(GameConstants.IIDX, version, user.id, profile)

    # Return that we updated
    return {
        "version": version,
    }


@iidx_pages.route("/options/name/update", methods=["POST"])
@jsonify
@loginrequired
def updatename() -> Dict[str, Any]:
    version = int(request.get_json()["version"])
    name = request.get_json()["name"]
    user = g.data.local.user.get_user(g.userID)
    if user is None:
        raise Exception("Unable to find user to update!")

    # Grab profile and update dj name
    profile = g.data.local.user.get_profile(GameConstants.IIDX, version, user.id)
    if profile is None:
        raise Exception("Unable to find profile to update!")
    if len(name) == 0 or len(name) > 6:
        raise Exception("Invalid profile name!")
    if re.match(r"^[-&$#\.\?\*!A-Z0-9]*$", name) is None:
        raise Exception("Invalid profile name!")
    profile.replace_str("name", name)
    g.data.local.user.put_profile(GameConstants.IIDX, version, user.id, profile)

    # Return that we updated
    return {
        "version": version,
        "name": name,
    }


@iidx_pages.route("/options/prefecture/update", methods=["POST"])
@jsonify
@loginrequired
def updateprefecture() -> Dict[str, Any]:
    version = int(request.get_json()["version"])
    prefecture = int(request.get_json()["prefecture"])
    user = g.data.local.user.get_user(g.userID)
    if user is None:
        raise Exception("Unable to find user to update!")

    # Grab profile and update prefecture
    profile = g.data.local.user.get_profile(GameConstants.IIDX, version, user.id)
    if profile is None:
        raise Exception("Unable to find profile to update!")
    profile.replace_int(
        "pid", RegionConstants.db_to_game_region(version >= 25, prefecture)
    )
    g.data.local.user.put_profile(GameConstants.IIDX, version, user.id, profile)

    # Return that we updated
    return {
        "version": version,
        "prefecture": prefecture,
    }


@iidx_pages.route("/rivals")
@loginrequired
def viewrivals() -> Response:
    frontend = IIDXFrontend(g.data, g.config, g.cache)
    rivals, djinfo = frontend.get_rivals(g.userID)

    return render_react(
        "IIDX Rivals",
        "iidx/rivals.react.js",
        {
            "userid": str(g.userID),
            "rivals": rivals,
            "players": djinfo,
            "versions": {
                version: name for (game, version, name) in frontend.all_games()
            },
        },
        {
            "refresh": url_for("iidx_pages.listrivals"),
            "search": url_for("iidx_pages.searchrivals"),
            "player": url_for("iidx_pages.viewplayer", userid=-1),
            "addrival": url_for("iidx_pages.addrival"),
            "removerival": url_for("iidx_pages.removerival"),
        },
    )


@iidx_pages.route("/rivals/list")
@jsonify
@loginrequired
def listrivals() -> Dict[str, Any]:
    frontend = IIDXFrontend(g.data, g.config, g.cache)
    rivals, djinfo = frontend.get_rivals(g.userID)

    return {
        "rivals": rivals,
        "players": djinfo,
    }


@iidx_pages.route("/rivals/search", methods=["POST"])
@jsonify
@loginrequired
def searchrivals() -> Dict[str, Any]:
    frontend = IIDXFrontend(g.data, g.config, g.cache)
    version = int(request.get_json()["version"])
    djname = request.get_json()["term"]

    # Try to treat the term as an extid
    extid = ID.parse_extid(djname)

    matches = set()
    profiles = g.data.remote.user.get_all_profiles(GameConstants.IIDX, version)
    for userid, profile in profiles:
        if profile.extid == extid or profile.get_str("name").lower() == djname.lower():
            matches.add(userid)

    djinfo = frontend.get_all_player_info(list(matches), allow_remote=True)
    return {
        "results": djinfo,
    }


@iidx_pages.route("/rivals/add", methods=["POST"])
@jsonify
@loginrequired
def addrival() -> Dict[str, Any]:
    frontend = IIDXFrontend(g.data, g.config, g.cache)
    version = int(request.get_json()["version"])
    rivaltype = request.get_json()["type"]
    other_userid = UserID(int(request.get_json()["userid"]))
    userid = g.userID

    # Add this rival link
    if rivaltype != "sp_rival" and rivaltype != "dp_rival":
        raise Exception(f"Invalid rival type {rivaltype}!")
    profile = g.data.remote.user.get_profile(GameConstants.IIDX, version, other_userid)
    if profile is None:
        raise Exception("Unable to find profile for rival!")

    g.data.local.user.put_link(
        GameConstants.IIDX,
        version,
        userid,
        rivaltype,
        other_userid,
        {},
    )

    # Now return updated rival info
    rivals, djinfo = frontend.get_rivals(userid)

    return {
        "rivals": rivals,
        "players": djinfo,
    }


@iidx_pages.route("/rivals/remove", methods=["POST"])
@jsonify
@loginrequired
def removerival() -> Dict[str, Any]:
    frontend = IIDXFrontend(g.data, g.config, g.cache)
    version = int(request.get_json()["version"])
    rivaltype = request.get_json()["type"]
    other_userid = UserID(int(request.get_json()["userid"]))
    userid = g.userID

    # Remove this rival link
    if rivaltype != "sp_rival" and rivaltype != "dp_rival":
        raise Exception(f"Invalid rival type {rivaltype}!")

    g.data.local.user.destroy_link(
        GameConstants.IIDX,
        version,
        userid,
        rivaltype,
        other_userid,
    )

    # Now return updated rival info
    rivals, djinfo = frontend.get_rivals(userid)

    return {
        "rivals": rivals,
        "players": djinfo,
    }
