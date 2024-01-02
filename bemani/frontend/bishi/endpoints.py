# vim: set fileencoding=utf-8
import re
from typing import Any, Dict
from flask import Blueprint, request, Response, url_for, abort

from bemani.common import GameConstants
from bemani.data import UserID
from bemani.frontend.app import loginrequired, jsonify, render_react
from bemani.frontend.bishi.bishi import BishiBashiFrontend
from bemani.frontend.templates import templates_location
from bemani.frontend.static import static_location
from bemani.frontend.types import g


bishi_pages = Blueprint(
    "bishi_pages",
    __name__,
    url_prefix=f"/{GameConstants.BISHI_BASHI.value}",
    template_folder=templates_location,
    static_folder=static_location,
)


@bishi_pages.route("/players")
@loginrequired
def viewplayers() -> Response:
    frontend = BishiBashiFrontend(g.data, g.config, g.cache)
    return render_react(
        "All BishiBashi Players",
        "bishi/allplayers.react.js",
        {"players": frontend.get_all_players()},
        {
            "refresh": url_for("bishi_pages.listplayers"),
            "player": url_for("bishi_pages.viewplayer", userid=-1),
        },
    )


@bishi_pages.route("/players/list")
@jsonify
@loginrequired
def listplayers() -> Dict[str, Any]:
    frontend = BishiBashiFrontend(g.data, g.config, g.cache)
    return {
        "players": frontend.get_all_players(),
    }


@bishi_pages.route("/players/<int:userid>")
@loginrequired
def viewplayer(userid: UserID) -> Response:
    frontend = BishiBashiFrontend(g.data, g.config, g.cache)
    djinfo = frontend.get_all_player_info([userid])[userid]
    if not djinfo:
        abort(404)
    latest_version = sorted(djinfo.keys(), reverse=True)[0]

    return render_react(
        f'{djinfo[latest_version]["name"]}\'s BishiBashi Profile',
        "bishi/player.react.js",
        {
            "playerid": userid,
            "own_profile": userid == g.userID,
            "player": djinfo,
            "versions": {version: name for (game, version, name) in frontend.all_games()},
        },
        {
            "refresh": url_for("bishi_pages.listplayer", userid=userid),
        },
    )


@bishi_pages.route("/players/<int:userid>/list")
@jsonify
@loginrequired
def listplayer(userid: UserID) -> Dict[str, Any]:
    frontend = BishiBashiFrontend(g.data, g.config, g.cache)
    djinfo = frontend.get_all_player_info([userid])[userid]

    return {
        "player": djinfo,
    }


@bishi_pages.route("/options")
@loginrequired
def viewsettings() -> Response:
    frontend = BishiBashiFrontend(g.data, g.config, g.cache)
    userid = g.userID
    djinfo = frontend.get_all_player_info([userid])[userid]
    if not djinfo:
        abort(404)

    return render_react(
        "BishiBashi Game Settings",
        "bishi/settings.react.js",
        {
            "player": djinfo,
            "versions": {version: name for (game, version, name) in frontend.all_games()},
        },
        {
            "updatename": url_for("bishi_pages.updatename"),
        },
    )


@bishi_pages.route("/options/name/update", methods=["POST"])
@jsonify
@loginrequired
def updatename() -> Dict[str, Any]:
    frontend = BishiBashiFrontend(g.data, g.config, g.cache)
    version = int(request.get_json()["version"])
    name = request.get_json()["name"]
    user = g.data.local.user.get_user(g.userID)
    if user is None:
        raise Exception("Unable to find user to update!")

    # Grab profile and update dj name
    profile = g.data.local.user.get_profile(GameConstants.BISHI_BASHI, version, user.id)
    if profile is None:
        raise Exception("Unable to find profile to update!")
    if len(name) == 0 or len(name) > 6:
        raise Exception("Invalid profile name!")

    # Convert lowercase to uppercase. We allow lowercase widetext in
    # the JS frontend to allow for Windows IME input of hiragana/katakana.
    def conv(char: str) -> str:
        i = ord(char)
        if i >= 0xFF41 and i <= 0xFF5A:
            return chr(i - (0xFF41 - 0xFF21))
        else:
            return char

    name = "".join([conv(a) for a in name])

    if (
        re.match(
            "^["
            + "\uFF20-\uFF3A"
            + "\uFF10-\uFF19"  # widetext A-Z, @
            + "\u3041-\u308D\u308F\u3092\u3093"  # widetext 0-9
            + "\u30A1-\u30ED\u30EF\u30F2\u30F3\u30FC"  # hiragana
            + "\u3000"  # katakana
            + "\u301C"  # widetext blank space
            + "\u30FB"  # widetext ~
            + "\u30FC"  # widetext middot
            + "\u2212"  # widetext long dash
            + "\u2605"  # widetext short dash
            + "\uFF01"  # widetext heavy star
            + "\uFF03"  # widetext !
            + "\uFF04"  # widetext #
            + "\uFF05"  # widetext $
            + "\uFF06"  # widetext %
            + "\uFF08"  # widetext &
            + "\uFF09"  # widetext (
            + "\uFF0A"  # widetext )
            + "\uFF0B"  # widetext *
            + "\uFF0F"  # widetext +
            + "\uFF1C"  # widetext /
            + "\uFF1D"  # widetext <
            + "\uFF1E"  # widetext =
            + "\uFF1F"  # widetext >
            + "\uFFE5"  # widetext ?
            + "]*$",  # widetext Yen symbol
            name,
        )
        is None
    ):
        raise Exception("Invalid profile name!")
    profile = frontend.update_name(profile, name)
    g.data.local.user.put_profile(GameConstants.BISHI_BASHI, version, user.id, profile)

    # Return that we updated
    return {
        "version": version,
        "name": frontend.sanitize_name(name),
    }
