# vim: set fileencoding=utf-8
import re
from typing import Any, Dict
from flask import Blueprint, request, Response, url_for, abort

from bemani.common import GameConstants
from bemani.data import UserID
from bemani.frontend.app import loginrequired, jsonify, render_react
from bemani.frontend.mga.mga import MetalGearArcadeFrontend
from bemani.frontend.templates import templates_location
from bemani.frontend.static import static_location
from bemani.frontend.types import g


mga_pages = Blueprint(
    "mga_pages",
    __name__,
    url_prefix=f"/{GameConstants.MGA.value}",
    template_folder=templates_location,
    static_folder=static_location,
)


@mga_pages.route("/players")
@loginrequired
def viewplayers() -> Response:
    frontend = MetalGearArcadeFrontend(g.data, g.config, g.cache)
    return render_react(
        "All MGA Players",
        "mga/allplayers.react.js",
        {"players": frontend.get_all_players()},
        {
            "refresh": url_for("mga_pages.listplayers"),
            "player": url_for("mga_pages.viewplayer", userid=-1),
        },
    )


@mga_pages.route("/players/list")
@jsonify
@loginrequired
def listplayers() -> Dict[str, Any]:
    frontend = MetalGearArcadeFrontend(g.data, g.config, g.cache)
    return {
        "players": frontend.get_all_players(),
    }


@mga_pages.route("/players/<int:userid>")
@loginrequired
def viewplayer(userid: UserID) -> Response:
    frontend = MetalGearArcadeFrontend(g.data, g.config, g.cache)
    djinfo = frontend.get_all_player_info([userid])[userid]
    if not djinfo:
        abort(404)
    latest_version = sorted(djinfo.keys(), reverse=True)[0]

    return render_react(
        f'{djinfo[latest_version]["name"]}\'s MGA Profile',
        "mga/player.react.js",
        {
            "playerid": userid,
            "own_profile": userid == g.userID,
            "player": djinfo,
            "versions": {
                version: name for (game, version, name) in frontend.all_games()
            },
        },
        {
            "refresh": url_for("mga_pages.listplayer", userid=userid),
        },
    )


@mga_pages.route("/players/<int:userid>/list")
@jsonify
@loginrequired
def listplayer(userid: UserID) -> Dict[str, Any]:
    frontend = MetalGearArcadeFrontend(g.data, g.config, g.cache)
    djinfo = frontend.get_all_player_info([userid])[userid]

    return {
        "player": djinfo,
    }


@mga_pages.route("/options")
@loginrequired
def viewsettings() -> Response:
    frontend = MetalGearArcadeFrontend(g.data, g.config, g.cache)
    userid = g.userID
    djinfo = frontend.get_all_player_info([userid])[userid]
    if not djinfo:
        abort(404)

    return render_react(
        "Metal Gear Arcade Game Settings",
        "mga/settings.react.js",
        {
            "player": djinfo,
            "versions": {
                version: name for (game, version, name) in frontend.all_games()
            },
        },
        {
            "updatename": url_for("mga_pages.updatename"),
        },
    )


@mga_pages.route("/options/name/update", methods=["POST"])
@jsonify
@loginrequired
def updatename() -> Dict[str, Any]:
    frontend = MetalGearArcadeFrontend(g.data, g.config, g.cache)
    version = int(request.get_json()["version"])
    name = request.get_json()["name"]
    user = g.data.local.user.get_user(g.userID)
    if user is None:
        raise Exception("Unable to find user to update!")

    # Grab profile and update dj name
    profile = g.data.local.user.get_profile(GameConstants.MGA, version, user.id)
    if profile is None:
        raise Exception("Unable to find profile to update!")
    if len(name) == 0 or len(name) > 8:
        raise Exception("Invalid profile name!")

    if (
        re.match(
            "^[" + "a-z" + "A-Z" + "0-9" + "@!?/=():*^[\\]#;\\-_{}$.+" + "]*$",
            name,
        )
        is None
    ):
        raise Exception("Invalid profile name!")
    profile = frontend.update_name(profile, name)
    g.data.local.user.put_profile(GameConstants.MGA, version, user.id, profile)

    # Return that we updated
    return {
        "version": version,
        "name": frontend.sanitize_name(name),
    }
