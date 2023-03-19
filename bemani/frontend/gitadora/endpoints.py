# vim: set fileencoding=utf-8
import re
from typing import Any, Dict
from flask import Blueprint, request, Response, url_for, abort

from bemani.common import ID, GameConstants
from bemani.data import UserID
from bemani.frontend.app import loginrequired, jsonify, render_react
from bemani.frontend.gitadora.gitadora import GitadoraFrontend
from bemani.frontend.templates import templates_location
from bemani.frontend.static import static_location
from bemani.frontend.types import g

gitadora_pages = Blueprint(
    "gitadora_pages",
    __name__,
    url_prefix=f"/{GameConstants.GITADORA.value}",
    template_folder=templates_location,
    static_folder=static_location,
)


@gitadora_pages.route("/scores")
@loginrequired
def viewnetworkscores() -> Response:
    # Only load the last 100 results for the initial fetch, so we can render faster
    frontend = GitadoraFrontend(g.data, g.config, g.cache)
    network_scores = frontend.get_network_scores(limit=100)
    if len(network_scores["attempts"]) > 10:
        network_scores["attempts"] = frontend.round_to_ten(network_scores["attempts"])

    return render_react(
        "Global Gitadora Scores",
        "gitadora/scores.react.js",
        {
            "attempts": network_scores["attempts"],
            "songs": frontend.get_all_songs(),
            "players": network_scores["players"],
            "versions": {
                version: name for (game, version, name) in frontend.all_games()
            },
            "shownames": True,
            "shownewrecords": False,
        },
        {
            "refresh": url_for("gitadora_pages.listnetworkscores"),
            "player": url_for("gitadora_pages.viewplayer", userid=-1),
            "individual_score": url_for("gitadora_pages.viewtopscores", musicid=-1),
        },
    )


@gitadora_pages.route("/scores/list")
@jsonify
@loginrequired
def listnetworkscores() -> Dict[str, Any]:
    frontend = GitadoraFrontend(g.data, g.config, g.cache)
    return frontend.get_network_scores()


@gitadora_pages.route("/scores/<int:userid>")
@loginrequired
def viewscores(userid: UserID) -> Response:
    frontend = GitadoraFrontend(g.data, g.config, g.cache)
    info = frontend.get_latest_player_info([userid]).get(userid)
    if info is None:
        abort(404)

    scores = frontend.get_scores(userid, limit=100)
    if len(scores) > 10:
        scores = frontend.round_to_ten(scores)

    return render_react(
        f'{info["name"]}\'s Gitadora Scores',
        "gitadora/scores.react.js",
        {
            "attempts": scores,
            "songs": frontend.get_all_songs(),
            "players": {},
            "versions": {
                version: name for (game, version, name) in frontend.all_games()
            },
            "shownames": False,
            "shownewrecords": True,
        },
        {
            "refresh": url_for("gitadora_pages.listscores", userid=userid),
            "player": url_for("gitadora_pages.viewplayer", userid=-1),
            "individual_score": url_for("gitadora_pages.viewtopscores", musicid=-1),
        },
    )


@gitadora_pages.route("/scores/<int:userid>/list")
@jsonify
@loginrequired
def listscores(userid: UserID) -> Dict[str, Any]:
    frontend = GitadoraFrontend(g.data, g.config, g.cache)
    return {
        "attempts": frontend.get_scores(userid),
        "players": {},
    }


@gitadora_pages.route("/records")
@loginrequired
def viewnetworkrecords() -> Response:
    frontend = GitadoraFrontend(g.data, g.config, g.cache)
    network_records = frontend.get_network_records()

    return render_react(
        "Global Gitadora Records",
        "gitadora/records.react.js",
        {
            "records": network_records["records"],
            "songs": frontend.get_all_songs(),
            "players": network_records["players"],
            "versions": {
                version: name for (game, version, name) in frontend.all_games()
            },
            "shownames": True,
            "showpersonalsort": False,
            "filterempty": False,
        },
        {
            "refresh": url_for("gitadora_pages.listnetworkrecords"),
            "player": url_for("gitadora_pages.viewplayer", userid=-1),
            "individual_score": url_for("gitadora_pages.viewtopscores", musicid=-1),
        },
    )


@gitadora_pages.route("/records/list")
@jsonify
@loginrequired
def listnetworkrecords() -> Dict[str, Any]:
    frontend = GitadoraFrontend(g.data, g.config, g.cache)
    return frontend.get_network_records()


@gitadora_pages.route("/records/<int:userid>")
@loginrequired
def viewrecords(userid: UserID) -> Response:
    frontend = GitadoraFrontend(g.data, g.config, g.cache)
    info = frontend.get_latest_player_info([userid]).get(userid)
    if info is None:
        abort(404)

    return render_react(
        f'{info["name"]}\'s Gitadora Records',
        "gitadora/records.react.js",
        {
            "records": frontend.get_records(userid),
            "songs": frontend.get_all_songs(),
            "players": {},
            "versions": {
                version: name for (game, version, name) in frontend.all_games()
            },
            "shownames": False,
            "showpersonalsort": True,
            "filterempty": True,
        },
        {
            "refresh": url_for("gitadora_pages.listrecords", userid=userid),
            "player": url_for("gitadora_pages.viewplayer", userid=-1),
            "individual_score": url_for("gitadora_pages.viewtopscores", musicid=-1),
        },
    )


@gitadora_pages.route("/records/<int:userid>/list")
@jsonify
@loginrequired
def listrecords(userid: UserID) -> Dict[str, Any]:
    frontend = GitadoraFrontend(g.data, g.config, g.cache)
    return {
        "records": frontend.get_records(userid),
        "players": {},
    }


@gitadora_pages.route("/topscores/<int:musicid>")
@loginrequired
def viewtopscores(musicid: int) -> Response:
    # We just want to find the latest mix that this song exists in
    frontend = GitadoraFrontend(g.data, g.config, g.cache)
    versions = sorted(
        [version for (game, version, name) in frontend.all_games()],
        reverse=True,
    )
    name = None
    artist = None
    genre = None
    difficulties = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    found = [
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
    ]

    for version in versions:
        for omniadd in [0, 10000]:
            for chart in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]:
                details = g.data.local.music.get_song(
                    GameConstants.GITADORA, version + omniadd, musicid, chart
                )
                if details is not None:
                    found[chart] = True
                    name = details.name
                    artist = details.artist
                    genre = details.genre
                    difficulties[chart] = details.data.get_int("difficulty", 13)
            if False not in found:
                break
        if False not in found:
            break

    if name is None:
        # Not a real song!
        abort(404)

    top_scores = frontend.get_top_scores(musicid)

    return render_react(
        f"Top Gitadora Scores for {artist} - {name}",
        "gitadora/topscores.react.js",
        {
            "name": name,
            "artist": artist,
            "genre": genre,
            "difficulties": difficulties,
            "players": top_scores["players"],
            "topscores": top_scores["topscores"],
        },
        {
            "refresh": url_for("gitadora_pages.listtopscores", musicid=musicid),
            "player": url_for("gitadora_pages.viewplayer", userid=-1),
        },
    )


@gitadora_pages.route("/topscores/<int:musicid>/list")
@jsonify
@loginrequired
def listtopscores(musicid: int) -> Dict[str, Any]:
    frontend = GitadoraFrontend(g.data, g.config, g.cache)
    return frontend.get_top_scores(musicid)


@gitadora_pages.route("/players")
@loginrequired
def viewplayers() -> Response:
    frontend = GitadoraFrontend(g.data, g.config, g.cache)
    return render_react(
        "All Gitadora Players",
        "gitadora/allplayers.react.js",
        {"players": frontend.get_all_players()},
        {
            "refresh": url_for("gitadora_pages.listplayers"),
            "player": url_for("gitadora_pages.viewplayer", userid=-1),
        },
    )


@gitadora_pages.route("/players/list")
@jsonify
@loginrequired
def listplayers() -> Dict[str, Any]:
    frontend = GitadoraFrontend(g.data, g.config, g.cache)
    return {
        "players": frontend.get_all_players(),
    }


@gitadora_pages.route("/players/<int:userid>")
@loginrequired
def viewplayer(userid: UserID) -> Response:
    frontend = GitadoraFrontend(g.data, g.config, g.cache)
    info = frontend.get_all_player_info([userid])[userid]
    if not info:
        abort(404)
    latest_version = sorted(info.keys(), reverse=True)[0]

    for version in info:
        gf_rival = g.data.local.user.get_link(
            GameConstants.GITADORA, version, g.userID, "gf_rival", userid
        )
        dm_rival = g.data.local.user.get_link(
            GameConstants.GITADORA, version, g.userID, "dm_rival", userid
        )
        info[version]["gf_rival"] = gf_rival is not None
        info[version]["dm_rival"] = dm_rival is not None

    return render_react(
        f'{info[latest_version]["name"]}\'s Gitadora Profile',
        "gitadora/player.react.js",
        {
            "playerid": userid,
            "own_profile": userid == g.userID,
            "player": info,
            "versions": {
                version: name for (game, version, name) in frontend.all_games()
            },
        },
        {
            "refresh": url_for("gitadora_pages.listplayer", userid=userid),
            "records": url_for("gitadora_pages.viewrecords", userid=userid),
            "scores": url_for("gitadora_pages.viewscores", userid=userid),
            "addrival": url_for("gitadora_pages.addrival"),
            "removerival": url_for("gitadora_pages.removerival"),
            "skills": url_for("gitadora_pages.showskills", userid=userid),
        },
    )


@gitadora_pages.route("/players/<int:userid>/list")
@jsonify
@loginrequired
def listplayer(userid: UserID) -> Dict[str, Any]:
    frontend = GitadoraFrontend(g.data, g.config, g.cache)
    info = frontend.get_all_player_info([userid])[userid]

    return {
        "player": info,
    }


@gitadora_pages.route("/options")
@loginrequired
def viewsettings() -> Response:
    frontend = GitadoraFrontend(g.data, g.config, g.cache)
    userid = g.userID
    info = frontend.get_all_player_info([userid])[userid]
    versions = sorted(
        [version for (game, version, name) in frontend.all_games()],
        reverse=True,
    )
    if not info:
        abort(404)

    return render_react(
        "Gitadora Game Settings",
        "gitadora/settings.react.js",
        {
            "player": info,
            "versions": {
                version: name for (game, version, name) in frontend.all_games()
            },
        },
        {
            "updatename": url_for("gitadora_pages.updatename"),
            "updatetitlesettings": url_for("gitadora_pages.updatetitlesettings"),
        },
    )


@gitadora_pages.route("/options/name/update", methods=["POST"])
@jsonify
@loginrequired
def updatename() -> Dict[str, Any]:
    version = int(request.get_json()["version"])
    name = request.get_json()["name"]
    user = g.data.local.user.get_user(g.userID)
    if user is None:
        raise Exception("Unable to find user to update!")

    # Grab profile and update name
    profile = g.data.local.user.get_profile(GameConstants.GITADORA, version, user.id)
    if profile is None:
        raise Exception("Unable to find profile to update!")
    if len(name) == 0 or len(name) > 9:
        raise Exception("Invalid profile name!")
    if (
        re.match(
            "^["
            + "\uFF20-\uFF3A"
            + "\uFF41-\uFF5A"  # widetext A-Z and @
            + "\uFF10-\uFF19"  # widetext a-z
            + "\uFF0C\uFF0E\uFF3F"  # widetext 0-9
            + "\u3041-\u308D\u308F\u3092\u3093"  # widetext ,._-!
            + "\u30A1-\u30ED\u30EF\u30F2\u30F3\u30FC"  # hiragana
            + "\u4E00-\u9FFF"  # katakana
            + "]*$",  # triditional chinese and simplified chinese
            name,
        )
        is None
    ):
        raise Exception("Invalid profile name!")
    profile.replace_str("name", name)
    g.data.local.user.put_profile(GameConstants.GITADORA, version, user.id, profile)

    # Return that we updated
    return {
        "version": version,
        "name": name,
    }


@gitadora_pages.route("/options/titlesettings/update", methods=["POST"])
@jsonify
@loginrequired
def updatetitlesettings() -> Dict[str, Any]:
    frontend = GitadoraFrontend(g.data, g.config, g.cache)
    title = request.get_json()["title"]
    version = int(request.get_json()["version"])
    user = g.data.local.user.get_user(g.userID)
    if user is None:
        raise Exception("Unable to find user to update!")

    profile = g.data.local.user.get_profile(GameConstants.GITADORA, version, user.id)
    if profile is None:
        raise Exception("Unable to find profile to update!")

    profile.replace_str("title", title)

    g.data.local.user.put_profile(GameConstants.GITADORA, version, user.id, profile)

    # Return updated arena message
    return {
        "title": title,
        "version": version,
    }


@gitadora_pages.route("/rivals")
@loginrequired
def viewrivals() -> Response:
    frontend = GitadoraFrontend(g.data, g.config, g.cache)
    rivals, playerinfo = frontend.get_rivals(g.userID)

    return render_react(
        "Gitadora Rivals",
        "gitadora/rivals.react.js",
        {
            "userid": str(g.userID),
            "rivals": rivals,
            "players": playerinfo,
            "versions": {
                version: name for (game, version, name) in frontend.all_games()
            },
        },
        {
            "refresh": url_for("gitadora_pages.listrivals"),
            "search": url_for("gitadora_pages.searchrivals"),
            "player": url_for("gitadora_pages.viewplayer", userid=-1),
            "addrival": url_for("gitadora_pages.addrival"),
            "removerival": url_for("gitadora_pages.removerival"),
        },
    )


@gitadora_pages.route("/rivals/list")
@jsonify
@loginrequired
def listrivals() -> Dict[str, Any]:
    frontend = GitadoraFrontend(g.data, g.config, g.cache)
    rivals, playerinfo = frontend.get_rivals(g.userID)

    return {
        "rivals": rivals,
        "players": playerinfo,
    }


@gitadora_pages.route("/rivals/search", methods=["POST"])
@jsonify
@loginrequired
def searchrivals() -> Dict[str, Any]:
    frontend = GitadoraFrontend(g.data, g.config, g.cache)
    version = int(request.get_json()["version"])
    name = request.get_json()["term"]

    # Try to treat the term as an extid
    extid = ID.parse_extid(name)

    matches = set()
    profiles = g.data.remote.user.get_all_profiles(GameConstants.GITADORA, version)
    for (userid, profile) in profiles:
        profile.get_str("name")
        if profile.extid == extid or profile.get_str("name").lower() == name.lower():
            matches.add(userid)

    playerinfo = frontend.get_all_player_info(list(matches), allow_remote=True)
    return {
        "results": playerinfo,
    }


@gitadora_pages.route("/rivals/add", methods=["POST"])
@jsonify
@loginrequired
def addrival() -> Dict[str, Any]:
    frontend = GitadoraFrontend(g.data, g.config, g.cache)
    version = int(request.get_json()["version"])
    rivaltype = request.get_json()["type"]
    other_userid = UserID(int(request.get_json()["userid"]))
    userid = g.userID

    # Add this rival link
    if rivaltype != "gf_rival" and rivaltype != "dm_rival":
        raise Exception(f"Invalid rival type {rivaltype}!")
    profile = g.data.remote.user.get_profile(
        GameConstants.GITADORA, version, other_userid
    )
    if profile is None:
        raise Exception("Unable to find profile for rival!")

    g.data.local.user.put_link(
        GameConstants.GITADORA,
        version,
        userid,
        rivaltype,
        other_userid,
        {},
    )

    # Now return updated rival info
    rivals, playerinfo = frontend.get_rivals(userid)

    return {
        "rivals": rivals,
        "players": playerinfo,
    }


@gitadora_pages.route("/rivals/remove", methods=["POST"])
@jsonify
@loginrequired
def removerival() -> Dict[str, Any]:
    frontend = GitadoraFrontend(g.data, g.config, g.cache)
    version = int(request.get_json()["version"])
    rivaltype = request.get_json()["type"]
    other_userid = UserID(int(request.get_json()["userid"]))
    userid = g.userID

    # Remove this rival link
    if rivaltype != "gf_rival" and rivaltype != "dm_rival":
        raise Exception(f"Invalid rival type {rivaltype}!")

    g.data.local.user.destroy_link(
        GameConstants.GITADORA,
        version,
        userid,
        rivaltype,
        other_userid,
    )

    # Now return updated rival info
    rivals, playerinfo = frontend.get_rivals(userid)

    return {
        "rivals": rivals,
        "players": playerinfo,
    }


@gitadora_pages.route("/players/<int:userid>/skills")
@loginrequired
def showskills(userid: UserID) -> Response:
    frontend = GitadoraFrontend(g.data, g.config, g.cache)
    info = frontend.get_all_player_info([userid])[userid]
    if not info:
        abort(404)
    latest_version = sorted(info.keys(), reverse=True)[0]
    for version in info:
        info[version]["gf_exist"] = frontend.format_skills(
            GameConstants.GITADORA,
            userid,
            version,
            info[version]["gf_exist"],
            "gf_exist",
        )
        info[version]["gf_new"] = frontend.format_skills(
            GameConstants.GITADORA, userid, version, info[version]["gf_new"], "gf_new"
        )
        info[version]["dm_exist"] = frontend.format_skills(
            GameConstants.GITADORA,
            userid,
            version,
            info[version]["dm_exist"],
            "dm_exist",
        )
        info[version]["dm_new"] = frontend.format_skills(
            GameConstants.GITADORA, userid, version, info[version]["dm_new"], "dm_new"
        )

    return render_react(
        f'{info[latest_version]["name"]}\'s Gitadora Skills',
        "gitadora/skills.react.js",
        {
            "playerid": userid,
            "player": info,
            "versions": {
                version: name for (game, version, name) in frontend.all_games()
            },
        },
        {
            "refresh": url_for("gitadora_pages.listplayer", userid=userid),
            "individual_score": url_for("gitadora_pages.viewtopscores", musicid=-1),
            "profile": url_for("gitadora_pages.viewplayer", userid=userid),
        },
    )
