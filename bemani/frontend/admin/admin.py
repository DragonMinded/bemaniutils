import random
from typing import Dict, Tuple, Any, Optional
from flask import Blueprint, request, Response, render_template, url_for

from bemani.backend.base import Base
from bemani.common import (
    CardCipher,
    CardCipherException,
    GameConstants,
    RegionConstants,
    ValidatedDict,
)
from bemani.data import Arcade, Machine, User, UserID, News, Event, Server, Client
from bemani.data.api.client import APIClient, NotAuthorizedAPIException, APIException
from bemani.frontend.app import (
    adminrequired,
    jsonify,
    valid_email,
    valid_username,
    valid_pin,
    render_react,
)
from bemani.frontend.gamesettings import get_game_settings
from bemani.frontend.iidx.iidx import IIDXFrontend
from bemani.frontend.jubeat.jubeat import JubeatFrontend
from bemani.frontend.popn.popn import PopnMusicFrontend
from bemani.frontend.templates import templates_location
from bemani.frontend.static import static_location
from bemani.frontend.types import g

admin_pages = Blueprint(
    "admin_pages",
    __name__,
    url_prefix="/admin",
    template_folder=templates_location,
    static_folder=static_location,
)


def format_arcade(arcade: Arcade) -> Dict[str, Any]:
    owners = []
    for owner in arcade.owners:
        user = g.data.local.user.get_user(owner)
        if user is not None:
            owners.append(user.username)
    return {
        "id": arcade.id,
        "name": arcade.name,
        "description": arcade.description,
        "region": arcade.region,
        "area": arcade.area or "",
        "paseli_enabled": arcade.data.get_bool("paseli_enabled"),
        "paseli_infinite": arcade.data.get_bool("paseli_infinite"),
        "mask_services_url": arcade.data.get_bool("mask_services_url"),
        "owners": owners,
    }


def format_machine(machine: Machine) -> Dict[str, Any]:
    return {
        "id": machine.id,
        "pcbid": machine.pcbid,
        "name": machine.name,
        "description": machine.description,
        "arcade": machine.arcade,
        "port": machine.port,
        "game": machine.game.value if machine.game else "any",
        "version": machine.version,
    }


def format_card(card: Tuple[str, Optional[UserID]]) -> Dict[str, Any]:
    owner = None
    if card[1] is not None:
        user = g.data.local.user.get_user(card[1])
        if user is not None:
            owner = user.username
    try:
        return {
            "number": CardCipher.encode(card[0]),
            "owner": owner,
            "id": card[1],
        }
    except CardCipherException:
        return {
            "number": "????????????????",
            "owner": owner,
            "id": card[1],
        }


def format_user(user: User) -> Dict[str, Any]:
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "admin": user.admin,
    }


def format_news(news: News) -> Dict[str, Any]:
    return {
        "id": news.id,
        "timestamp": news.timestamp,
        "title": news.title,
        "body": news.body,
    }


def format_event(event: Event) -> Dict[str, Any]:
    return {
        "id": event.id,
        "timestamp": event.timestamp,
        "userid": event.userid,
        "arcadeid": event.arcadeid,
        "type": event.type,
        "data": event.data,
    }


def format_client(client: Client) -> Dict[str, Any]:
    return {
        "id": client.id,
        "name": client.name,
        "token": client.token,
    }


def format_server(server: Server) -> Dict[str, Any]:
    return {
        "id": server.id,
        "uri": server.uri,
        "token": server.token,
        "allow_stats": server.allow_stats,
        "allow_scores": server.allow_scores,
    }


@admin_pages.route("/")
@adminrequired
def viewsettings() -> Response:
    return Response(
        render_template(
            "admin/settings.html",
            **{
                "title": "Network Settings",
                "config": g.config,
                "region": RegionConstants.LUT,
            },
        )
    )


@admin_pages.route("/events")
@adminrequired
def viewevents() -> Response:
    iidx = IIDXFrontend(g.data, g.config, g.cache)
    jubeat = JubeatFrontend(g.data, g.config, g.cache)
    pnm = PopnMusicFrontend(g.data, g.config, g.cache)
    return render_react(
        "Events",
        "admin/events.react.js",
        {
            "events": [format_event(event) for event in g.data.local.network.get_events(limit=100)],
            "users": {user.id: user.username for user in g.data.local.user.get_all_users()},
            "arcades": {arcade.id: arcade.name for arcade in g.data.local.machine.get_all_arcades()},
            "iidxsongs": iidx.get_all_songs(),
            "jubeatsongs": jubeat.get_all_songs(),
            "pnmsongs": pnm.get_all_songs(),
            "iidxversions": {version: name for (game, version, name) in iidx.all_games()},
            "jubeatversions": {version: name for (game, version, name) in jubeat.all_games()},
            "pnmversions": {version: name for (game, version, name) in pnm.all_games()},
        },
        {
            "refresh": url_for("admin_pages.listevents", since=-1),
            "backfill": url_for("admin_pages.backfillevents", until=-1),
            "viewuser": url_for("admin_pages.viewuser", userid=-1),
            "jubeatsong": (
                url_for("jubeat_pages.viewtopscores", musicid=-1) if GameConstants.JUBEAT in g.config.support else None
            ),
            "iidxsong": (
                url_for("iidx_pages.viewtopscores", musicid=-1) if GameConstants.IIDX in g.config.support else None
            ),
            "pnmsong": (
                url_for("popn_pages.viewtopscores", musicid=-1)
                if GameConstants.POPN_MUSIC in g.config.support
                else None
            ),
        },
    )


@admin_pages.route("/events/backfill/<int:until>")
@jsonify
@adminrequired
def backfillevents(until: int) -> Dict[str, Any]:
    return {
        "events": [format_event(event) for event in g.data.local.network.get_events(until_id=until, limit=1000)],
    }


@admin_pages.route("/events/list/<int:since>")
@jsonify
@adminrequired
def listevents(since: int) -> Dict[str, Any]:
    return {
        "events": [format_event(event) for event in g.data.local.network.get_events(since_id=since)],
        "users": {user.id: user.username for user in g.data.local.user.get_all_users()},
        "arcades": {arcade.id: arcade.name for arcade in g.data.local.machine.get_all_arcades()},
    }


@admin_pages.route("/api")
@adminrequired
def viewapi() -> Response:
    return render_react(
        "Data API",
        "admin/api.react.js",
        {
            "clients": [format_client(client) for client in g.data.local.api.get_all_clients()],
            "servers": [format_server(server) for server in g.data.local.api.get_all_servers()],
        },
        {
            "addclient": url_for("admin_pages.addclient"),
            "updateclient": url_for("admin_pages.updateclient"),
            "removeclient": url_for("admin_pages.removeclient"),
            "addserver": url_for("admin_pages.addserver"),
            "updateserver": url_for("admin_pages.updateserver"),
            "removeserver": url_for("admin_pages.removeserver"),
            "queryserver": url_for("admin_pages.queryserver", serverid=-1),
        },
    )


@admin_pages.route("/arcades")
@adminrequired
def viewarcades() -> Response:
    return render_react(
        "Arcades",
        "admin/arcades.react.js",
        {
            "arcades": [format_arcade(arcade) for arcade in g.data.local.machine.get_all_arcades()],
            "regions": RegionConstants.LUT,
            "usernames": g.data.local.user.get_all_usernames(),
            "paseli_enabled": g.config.paseli.enabled,
            "paseli_infinite": g.config.paseli.infinite,
            "default_region": g.config.server.region,
            "default_area": g.config.server.area,
            "mask_services_url": False,
        },
        {
            "addarcade": url_for("admin_pages.addarcade"),
            "updatearcade": url_for("admin_pages.updatearcade"),
            "removearcade": url_for("admin_pages.removearcade"),
        },
    )


@admin_pages.route("/pcbids")
@adminrequired
def viewmachines() -> Response:
    games: Dict[str, Dict[int, str]] = {}
    for game, version, name in Base.all_games():
        if game.value not in games:
            games[game.value] = {}
        games[game.value][version] = name

    return render_react(
        "Machines",
        "admin/machines.react.js",
        {
            "machines": [format_machine(machine) for machine in g.data.local.machine.get_all_machines()],
            "arcades": {arcade.id: arcade.name for arcade in g.data.local.machine.get_all_arcades()},
            "series": {
                GameConstants.BISHI_BASHI.value: "BishiBashi",
                GameConstants.DDR.value: "DDR",
                GameConstants.IIDX.value: "IIDX",
                GameConstants.JUBEAT.value: "Jubeat",
                GameConstants.MGA.value: "Metal Gear Arcade",
                GameConstants.MUSECA.value: "MÚSECA",
                GameConstants.POPN_MUSIC.value: "Pop'n Music",
                GameConstants.REFLEC_BEAT.value: "Reflec Beat",
                GameConstants.SDVX.value: "SDVX",
            },
            "games": games,
            "enforcing": g.config.server.enforce_pcbid,
        },
        {
            "refresh": url_for("admin_pages.listmachines"),
            "generatepcbid": url_for("admin_pages.generatepcbid"),
            "addpcbid": url_for("admin_pages.addpcbid"),
            "updatepcbid": url_for("admin_pages.updatepcbid"),
            "removepcbid": url_for("admin_pages.removepcbid"),
        },
    )


@admin_pages.route("/cards")
@adminrequired
def viewcards() -> Response:
    return render_react(
        "Cards",
        "admin/cards.react.js",
        {
            "cards": [format_card(card) for card in g.data.local.user.get_all_cards()],
            "usernames": g.data.local.user.get_all_usernames(),
        },
        {
            "addcard": url_for("admin_pages.addcard"),
            "removecard": url_for("admin_pages.removecard"),
            "viewuser": url_for("admin_pages.viewuser", userid=-1),
        },
    )


@admin_pages.route("/users")
@adminrequired
def viewusers() -> Response:
    return render_react(
        "Users",
        "admin/users.react.js",
        {
            "users": [format_user(user) for user in g.data.local.user.get_all_users()],
        },
        {
            "searchusers": url_for("admin_pages.searchusers"),
            "viewuser": url_for("admin_pages.viewuser", userid=-1),
        },
    )


@admin_pages.route("/news")
@adminrequired
def viewnews() -> Response:
    return render_react(
        "News",
        "admin/news.react.js",
        {
            "news": [format_news(news) for news in g.data.local.network.get_all_news()],
        },
        {
            "removenews": url_for("admin_pages.removenews"),
            "addnews": url_for("admin_pages.addnews"),
            "updatenews": url_for("admin_pages.updatenews"),
        },
    )


@admin_pages.route("/gamesettings")
@adminrequired
def viewgamesettings() -> Response:
    return render_react(
        "Game Settings",
        "admin/gamesettings.react.js",
        {
            "game_settings": get_game_settings(g.data, g.data.local.machine.DEFAULT_SETTINGS_ARCADE),
        },
        {
            "update_settings": url_for("admin_pages.updatesettings"),
        },
    )


@admin_pages.route("/users/<int:userid>")
@adminrequired
def viewuser(userid: int) -> Response:
    # Cast the userID.
    userid = UserID(userid)
    user = g.data.local.user.get_user(userid)

    def __format_card(card: str) -> str:
        try:
            return CardCipher.encode(card)
        except CardCipherException:
            return "????????????????"

    cards = [__format_card(card) for card in g.data.local.user.get_cards(userid)]
    arcades = g.data.local.machine.get_all_arcades()
    return render_react(
        "User",
        "admin/user.react.js",
        {
            "user": {
                "email": user.email,
                "username": user.username,
            },
            "cards": cards,
            "arcades": {arcade.id: arcade.name for arcade in arcades},
            "balances": {arcade.id: g.data.local.user.get_balance(userid, arcade.id) for arcade in arcades},
            "events": [
                format_event(event)
                for event in g.data.local.network.get_events(userid=userid, event="paseli_transaction")
            ],
        },
        {
            "refresh": url_for("admin_pages.listuser", userid=userid),
            "removeusercard": url_for("admin_pages.removeusercard", userid=userid),
            "addusercard": url_for("admin_pages.addusercard", userid=userid),
            "updatebalance": url_for("admin_pages.updatebalance", userid=userid),
            "updateusername": url_for("admin_pages.updateusername", userid=userid),
            "updateemail": url_for("admin_pages.updateemail", userid=userid),
            "updatepin": url_for("admin_pages.updatepin", userid=userid),
            "updatepassword": url_for("admin_pages.updatepassword", userid=userid),
        },
    )


@admin_pages.route("/users/<int:userid>/list")
@jsonify
@adminrequired
def listuser(userid: int) -> Dict[str, Any]:
    # Cast the userID.
    userid = UserID(userid)

    def __format_card(card: str) -> str:
        try:
            return CardCipher.encode(card)
        except CardCipherException:
            return "????????????????"

    cards = [__format_card(card) for card in g.data.local.user.get_cards(userid)]
    arcades = g.data.local.machine.get_all_arcades()
    return {
        "cards": cards,
        "arcades": {arcade.id: arcade.name for arcade in arcades},
        "balances": {arcade.id: g.data.local.user.get_balance(userid, arcade.id) for arcade in arcades},
        "events": [
            format_event(event) for event in g.data.local.network.get_events(userid=userid, event="paseli_transaction")
        ],
    }


@admin_pages.route("/arcades/list")
@jsonify
@adminrequired
def listmachines() -> Dict[str, Any]:
    return {
        "machines": [format_machine(machine) for machine in g.data.local.machine.get_all_machines()],
        "arcades": {arcade.id: arcade.name for arcade in g.data.local.machine.get_all_arcades()},
    }


@admin_pages.route("/arcades/update", methods=["POST"])
@jsonify
@adminrequired
def updatearcade() -> Dict[str, Any]:
    # Attempt to look this arcade up
    new_values = request.get_json()["arcade"]
    arcade = g.data.local.machine.get_arcade(new_values["id"])
    if arcade is None:
        raise Exception("Unable to find arcade to update!")

    arcade.name = new_values["name"]
    arcade.description = new_values["description"]
    arcade.region = new_values["region"]
    arcade.area = new_values["area"] or None
    arcade.data.replace_bool("paseli_enabled", new_values["paseli_enabled"])
    arcade.data.replace_bool("paseli_infinite", new_values["paseli_infinite"])
    arcade.data.replace_bool("mask_services_url", new_values["mask_services_url"])
    owners = []
    for owner in new_values["owners"]:
        ownerid = g.data.local.user.from_username(owner)
        if ownerid is not None:
            owners.append(ownerid)
    owners = list(set(owners))
    arcade.owners = owners
    g.data.local.machine.put_arcade(arcade)

    # Just return all arcades for ease of updating
    return {
        "arcades": [format_arcade(arcade) for arcade in g.data.local.machine.get_all_arcades()],
    }


@admin_pages.route("/arcades/add", methods=["POST"])
@jsonify
@adminrequired
def addarcade() -> Dict[str, Any]:
    # Attempt to look this arcade up
    new_values = request.get_json()["arcade"]

    if len(new_values["name"]) == 0:
        raise Exception("Please name your new arcade!")
    if len(new_values["description"]) == 0:
        raise Exception("Please describe your new arcade!")
    owners = []
    for owner in new_values["owners"]:
        ownerid = g.data.local.user.from_username(owner)
        if ownerid is not None:
            owners.append(ownerid)
    owners = list(set(owners))

    g.data.local.machine.create_arcade(
        new_values["name"],
        new_values["description"],
        new_values["region"],
        new_values["area"] or None,
        {
            "paseli_enabled": new_values["paseli_enabled"],
            "paseli_infinite": new_values["paseli_infinite"],
            "mask_services_url": new_values["mask_services_url"],
        },
        owners,
    )

    # Just return all arcades for ease of updating
    return {
        "arcades": [format_arcade(arcade) for arcade in g.data.local.machine.get_all_arcades()],
    }


@admin_pages.route("/arcades/remove", methods=["POST"])
@jsonify
@adminrequired
def removearcade() -> Dict[str, Any]:
    # Attempt to look this arcade up
    arcadeid = request.get_json()["arcadeid"]
    arcade = g.data.local.machine.get_arcade(arcadeid)
    if arcade is None:
        raise Exception("Unable to find arcade to delete!")
    g.data.local.machine.destroy_arcade(arcadeid)

    # Just return all arcades for ease of updating
    return {
        "arcades": [format_arcade(arcade) for arcade in g.data.local.machine.get_all_arcades()],
    }


@admin_pages.route("/clients/update", methods=["POST"])
@jsonify
@adminrequired
def updateclient() -> Dict[str, Any]:
    # Attempt to look this client up
    new_values = request.get_json()["client"]
    client = g.data.local.api.get_client(new_values["id"])
    if client is None:
        raise Exception("Unable to find client to update!")

    if len(new_values["name"]) == 0:
        raise Exception("Client names must be at least one character long!")

    client.name = new_values["name"]
    g.data.local.api.put_client(client)

    # Just return all clients for ease of updating
    return {
        "clients": [format_client(client) for client in g.data.local.api.get_all_clients()],
    }


@admin_pages.route("/clients/add", methods=["POST"])
@jsonify
@adminrequired
def addclient() -> Dict[str, Any]:
    # Attempt to look this client up
    new_values = request.get_json()["client"]

    if len(new_values["name"]) == 0:
        raise Exception("Please name your new client!")

    g.data.local.api.create_client(
        new_values["name"],
    )

    # Just return all clientss for ease of updating
    return {
        "clients": [format_client(client) for client in g.data.local.api.get_all_clients()],
    }


@admin_pages.route("/clients/remove", methods=["POST"])
@jsonify
@adminrequired
def removeclient() -> Dict[str, Any]:
    # Attempt to look this client up
    clientid = request.get_json()["clientid"]
    client = g.data.local.api.get_client(clientid)
    if client is None:
        raise Exception("Unable to find client to delete!")
    g.data.local.api.destroy_client(clientid)

    # Just return all clients for ease of updating
    return {
        "clients": [format_client(client) for client in g.data.local.api.get_all_clients()],
    }


@admin_pages.route("/server/<int:serverid>/info")
@jsonify
@adminrequired
def queryserver(serverid: int) -> Dict[str, Any]:
    # Attempt to look this server up
    server = g.data.local.api.get_server(serverid)
    if server is None:
        raise Exception("Unable to find server to query!")

    client = APIClient(server.uri, server.token, False, False)
    try:
        serverinfo = client.get_server_info()
        info = {
            "name": serverinfo["name"],
            "email": serverinfo["email"],
        }
        info["status"] = "ok" if APIClient.API_VERSION in serverinfo["versions"] else "badversion"
    except NotAuthorizedAPIException:
        info = {
            "name": "unknown",
            "email": "unknown",
            "status": "badauth",
        }
    except APIException:
        info = {
            "name": "unknown",
            "email": "unknown",
            "status": "error",
        }

    return info


@admin_pages.route("/servers/update", methods=["POST"])
@jsonify
@adminrequired
def updateserver() -> Dict[str, Any]:
    # Attempt to look this server up
    new_values = request.get_json()["server"]
    server = g.data.local.api.get_server(new_values["id"])
    if server is None:
        raise Exception("Unable to find server to update!")

    if len(new_values["uri"]) == 0:
        raise Exception("Please provide a valid connection URI for this server!")
    if len(new_values["token"]) == 0 or len(new_values["token"]) > 64:
        raise Exception("Please provide a valid connection token for this server!")

    server.uri = new_values["uri"]
    server.token = new_values["token"]
    server.allow_stats = new_values["allow_stats"]
    server.allow_scores = new_values["allow_scores"]
    g.data.local.api.put_server(server)

    # Just return all servers for ease of updating
    return {
        "servers": [format_server(server) for server in g.data.local.api.get_all_servers()],
    }


@admin_pages.route("/servers/add", methods=["POST"])
@jsonify
@adminrequired
def addserver() -> Dict[str, Any]:
    # Attempt to look this server up
    new_values = request.get_json()["server"]

    if len(new_values["uri"]) == 0:
        raise Exception("Please provide a connection URI for the new server!")
    if len(new_values["token"]) == 0 or len(new_values["token"]) > 64:
        raise Exception("Please provide a valid connection token for the new server!")

    g.data.local.api.create_server(
        new_values["uri"],
        new_values["token"],
    )

    # Just return all serverss for ease of updating
    return {
        "servers": [format_server(server) for server in g.data.local.api.get_all_servers()],
    }


@admin_pages.route("/servers/remove", methods=["POST"])
@jsonify
@adminrequired
def removeserver() -> Dict[str, Any]:
    # Attempt to look this server up
    serverid = request.get_json()["serverid"]
    server = g.data.local.api.get_server(serverid)
    if server is None:
        raise Exception("Unable to find server to delete!")
    g.data.local.api.destroy_server(serverid)

    # Just return all servers for ease of updating
    return {
        "servers": [format_server(server) for server in g.data.local.api.get_all_servers()],
    }


@admin_pages.route("/pcbids/generate", methods=["POST"])
@jsonify
@adminrequired
def generatepcbid() -> Dict[str, Any]:
    # Attempt to look this arcade up
    new_pcbid = request.get_json()["machine"]
    if new_pcbid["arcade"] is not None:
        arcade = g.data.local.machine.get_arcade(new_pcbid["arcade"])
        if arcade is None:
            raise Exception("Unable to find arcade to link PCBID to!")

    # Will be set by the game on boot.
    name: str = "なし"
    pcbid: Optional[str] = None
    while pcbid is None:
        # Generate a new PCBID, check for uniqueness
        potential_pcbid = "01201000000000" + "".join([random.choice("0123456789ABCDEF") for _ in range(6)])
        if g.data.local.machine.get_machine(potential_pcbid) is None:
            pcbid = potential_pcbid

    g.data.local.machine.create_machine(pcbid, name, new_pcbid["description"], new_pcbid["arcade"])

    # Just return all machines for ease of updating
    return {
        "machines": [format_machine(machine) for machine in g.data.local.machine.get_all_machines()],
    }


@admin_pages.route("/pcbids/add", methods=["POST"])
@jsonify
@adminrequired
def addpcbid() -> Dict[str, Any]:
    # Attempt to look this arcade up
    new_pcbid = request.get_json()["machine"]
    if new_pcbid["arcade"] is not None:
        arcade = g.data.local.machine.get_arcade(new_pcbid["arcade"])
        if arcade is None:
            raise Exception("Unable to find arcade to link PCBID to!")

    # Verify that the PCBID is valid
    potential_pcbid = "".join([c for c in new_pcbid["pcbid"].upper() if c in "0123456789ABCDEF"])
    if len(potential_pcbid) != len(new_pcbid["pcbid"]):
        raise Exception("Invalid characters in PCBID!")
    if len(potential_pcbid) != 20:
        raise Exception("PCBID has invalid length!")

    if g.data.local.machine.get_machine(potential_pcbid) is not None:
        raise Exception("PCBID already exists!")

    # Will be set by the game on boot.
    name = "なし"
    g.data.local.machine.create_machine(potential_pcbid, name, new_pcbid["description"], new_pcbid["arcade"])

    # Just return all machines for ease of updating
    return {
        "machines": [format_machine(machine) for machine in g.data.local.machine.get_all_machines()],
    }


@admin_pages.route("/pcbids/update", methods=["POST"])
@jsonify
@adminrequired
def updatepcbid() -> Dict[str, Any]:
    # Attempt to look this machine up
    machine = request.get_json()["machine"]
    if machine["arcade"] is not None:
        arcade = g.data.local.machine.get_arcade(machine["arcade"])
        if arcade is None:
            raise Exception("Unable to find arcade to link PCBID to!")

    # Make sure we don't duplicate port assignments
    other_pcbid = g.data.local.machine.from_port(machine["port"])
    if other_pcbid is not None and other_pcbid != machine["pcbid"]:
        raise Exception(f"The specified port is already in use by '{other_pcbid}'!")

    if machine["port"] < 1 or machine["port"] > 65535:
        raise Exception("The specified port is out of range!")

    current_machine = g.data.local.machine.get_machine(machine["pcbid"])
    current_machine.description = machine["description"]
    current_machine.arcade = machine["arcade"]
    current_machine.port = machine["port"]
    current_machine.game = None if machine["game"] == "any" else GameConstants(machine["game"])
    current_machine.version = None if machine["game"] == "any" else machine["version"]
    g.data.local.machine.put_machine(current_machine)

    # Just return all machines for ease of updating
    return {
        "machines": [format_machine(machine) for machine in g.data.local.machine.get_all_machines()],
    }


@admin_pages.route("/pcbids/remove", methods=["POST"])
@jsonify
@adminrequired
def removepcbid() -> Dict[str, Any]:
    # Attempt to look this machine up
    pcbid = request.get_json()["pcbid"]
    if g.data.local.machine.get_machine(pcbid) is None:
        raise Exception("Unable to find PCBID to delete!")

    g.data.local.machine.destroy_machine(pcbid)

    # Just return all machines for ease of updating
    return {
        "machines": [format_machine(machine) for machine in g.data.local.machine.get_all_machines()],
    }


@admin_pages.route("/cards/remove", methods=["POST"])
@jsonify
@adminrequired
def removecard() -> Dict[str, Any]:
    # Grab card, convert it
    card = request.get_json()["card"]
    try:
        cardid = CardCipher.decode(card)
    except CardCipherException:
        raise Exception("Invalid card number!")

    # Make sure it is our card
    userid = g.data.local.user.from_cardid(cardid)

    # Remove it from the user's account
    g.data.local.user.destroy_card(userid, cardid)

    # Return new card list
    return {
        "cards": [format_card(card) for card in g.data.local.user.get_all_cards()],
    }


@admin_pages.route("/cards/add", methods=["POST"])
@jsonify
@adminrequired
def addcard() -> Dict[str, Any]:
    # Grab card, convert it
    card = request.get_json()["card"]
    try:
        cardid = CardCipher.decode(card["number"])
    except CardCipherException:
        raise Exception("Invalid card number!")

    # Make sure it is our card
    userid = g.data.local.user.from_username(card["owner"])
    if userid is None:
        raise Exception("Cannot find user to add card to!")

    # See if it is already claimed
    curuserid = g.data.local.user.from_cardid(cardid)
    if curuserid is not None:
        raise Exception("This card is already in use!")

    # Add it to the user's account
    g.data.local.user.add_card(userid, cardid)

    # Return new card list
    return {
        "cards": [format_card(card) for card in g.data.local.user.get_all_cards()],
    }


@admin_pages.route("/users/search", methods=["POST"])
@jsonify
@adminrequired
def searchusers() -> Dict[str, Any]:
    # Grab card, convert it
    searchdetails = request.get_json()["user_search"]
    if len(searchdetails["card"]) > 0:
        try:
            cardid = CardCipher.decode(searchdetails["card"])
            actual_userid = g.data.local.user.from_cardid(cardid)
            if actual_userid is None:
                # Force a non-match below
                actual_userid = UserID(-1)
        except CardCipherException:
            actual_userid = UserID(-1)
    else:
        actual_userid = None

    def match(user: User) -> bool:
        if actual_userid is not None:
            return user.id == actual_userid
        else:
            return True

    return {
        "users": [format_user(user) for user in g.data.local.user.get_all_users() if match(user)],
    }


@admin_pages.route("/users/<int:userid>/balance/update", methods=["POST"])
@jsonify
@adminrequired
def updatebalance(userid: int) -> Dict[str, Any]:
    # Cast the userID.
    userid = UserID(userid)

    credits = request.get_json()["credits"]
    user = g.data.local.user.get_user(userid)
    arcades = g.data.local.machine.get_all_arcades()

    # Make sure the user ID is valid
    if user is None:
        raise Exception("Cannot find user to update!")

    # Update balances
    for arcadeid in credits:
        balance = g.data.local.user.update_balance(userid, arcadeid, credits[arcadeid])
        if balance is not None:
            g.data.local.network.put_event(
                "paseli_transaction",
                {
                    "delta": credits[arcadeid],
                    "balance": balance,
                    "reason": "admin adjustment",
                },
                userid=userid,
                arcadeid=arcadeid,
            )

    return {
        "arcades": {arcade.id: arcade.name for arcade in arcades},
        "balances": {arcade.id: g.data.local.user.get_balance(userid, arcade.id) for arcade in arcades},
        "events": [
            format_event(event) for event in g.data.local.network.get_events(userid=userid, event="paseli_transaction")
        ],
    }


@admin_pages.route("/users/<int:userid>/username/update", methods=["POST"])
@jsonify
@adminrequired
def updateusername(userid: int) -> Dict[str, Any]:
    # Cast the userID.
    userid = UserID(userid)

    username = request.get_json()["username"]
    user = g.data.local.user.get_user(userid)
    # Make sure the user ID is valid
    if user is None:
        raise Exception("Cannot find user to update!")

    if not valid_username(username):
        raise Exception("Invalid username!")

    # Make sure this user ID isn't taken
    potential_userid = g.data.local.user.from_username(username)
    if potential_userid is not None and potential_userid != userid:
        raise Exception("That username is already taken!")

    # Update the user
    user.username = username
    g.data.local.user.put_user(user)

    return {
        "username": username,
    }


@admin_pages.route("/users/<int:userid>/email/update", methods=["POST"])
@jsonify
@adminrequired
def updateemail(userid: int) -> Dict[str, Any]:
    # Cast the userID.
    userid = UserID(userid)

    email = request.get_json()["email"]
    user = g.data.local.user.get_user(userid)
    # Make sure the user ID is valid
    if user is None:
        raise Exception("Cannot find user to update!")

    if not valid_email(email):
        raise Exception("Invalid email!")

    # Update the user
    user.email = email
    g.data.local.user.put_user(user)

    return {
        "email": email,
    }


@admin_pages.route("/users/<int:userid>/pin/update", methods=["POST"])
@jsonify
@adminrequired
def updatepin(userid: int) -> Dict[str, Any]:
    # Cast the userID.
    userid = UserID(userid)

    pin = request.get_json()["pin"]
    user = g.data.local.user.get_user(userid)
    # Make sure the user ID is valid
    if user is None:
        raise Exception("Cannot find user to update!")

    if not valid_pin(pin, "card"):
        raise Exception("Invalid pin, must be exactly 4 digits!")

    # Update the user
    g.data.local.user.update_pin(userid, pin)

    return {}


@admin_pages.route("/users/<int:userid>/password/update", methods=["POST"])
@jsonify
@adminrequired
def updatepassword(userid: int) -> Dict[str, Any]:
    # Cast the userID.
    userid = UserID(userid)

    new1 = request.get_json()["new1"]
    new2 = request.get_json()["new2"]
    user = g.data.local.user.get_user(userid)
    # Make sure the user ID is valid
    if user is None:
        raise Exception("Cannot find user to update!")

    # Now, make sure that the passwords match
    if new1 != new2:
        raise Exception("Passwords do not match each other!")

    # Now, make sure passwords are long enough
    if len(new1) < 6:
        raise Exception("Password is not long enough!")

    # Update the user
    g.data.local.user.update_password(userid, new1)

    return {}


@admin_pages.route("/users/<int:userid>/cards/remove", methods=["POST"])
@jsonify
@adminrequired
def removeusercard(userid: int) -> Dict[str, Any]:
    # Cast the userID.
    userid = UserID(userid)

    # Grab card, convert it
    card = request.get_json()["card"]
    try:
        cardid = CardCipher.decode(card)
    except CardCipherException:
        raise Exception("Invalid card number!")
    user = g.data.local.user.get_user(userid)
    # Make sure the user ID is valid
    if user is None:
        raise Exception("Cannot find user to update!")

    # Remove it from the user's account
    g.data.local.user.destroy_card(userid, cardid)

    # Return new card list
    return {
        "cards": [CardCipher.encode(card) for card in g.data.local.user.get_cards(userid)],
    }


@admin_pages.route("/users/<int:userid>/cards/add", methods=["POST"])
@jsonify
@adminrequired
def addusercard(userid: int) -> Dict[str, Any]:
    # Cast the userID.
    userid = UserID(userid)

    # Grab card, convert it
    card = request.get_json()["card"]
    try:
        cardid = CardCipher.decode(card)
    except CardCipherException:
        raise Exception("Invalid card number!")
    user = g.data.local.user.get_user(userid)
    # Make sure the user ID is valid
    if user is None:
        raise Exception("Cannot find user to update!")

    # See if it is already claimed
    curuserid = g.data.local.user.from_cardid(cardid)
    if curuserid is not None:
        raise Exception("This card is already in use!")

    # Add it to the user's account
    g.data.local.user.add_card(userid, cardid)

    # Return new card list
    return {
        "cards": [CardCipher.encode(card) for card in g.data.local.user.get_cards(userid)],
    }


@admin_pages.route("/news/add", methods=["POST"])
@jsonify
@adminrequired
def addnews() -> Dict[str, Any]:
    news = request.get_json()["news"]
    if len(news["title"]) == 0:
        raise Exception("Please provide a title!")
    if len(news["body"]) == 0:
        raise Exception("Please provide a body!")

    g.data.local.network.create_news(news["title"], news["body"])

    return {
        "news": [format_news(news) for news in g.data.local.network.get_all_news()],
    }


@admin_pages.route("/news/remove", methods=["POST"])
@jsonify
@adminrequired
def removenews() -> Dict[str, Any]:
    newsid = request.get_json()["newsid"]
    if g.data.local.network.get_news(newsid) is None:
        raise Exception("Unable to find entry to delete!")

    g.data.local.network.destroy_news(newsid)

    return {
        "news": [format_news(news) for news in g.data.local.network.get_all_news()],
    }


@admin_pages.route("/news/update", methods=["POST"])
@jsonify
@adminrequired
def updatenews() -> Dict[str, Any]:
    new_news = request.get_json()["news"]
    if g.data.local.network.get_news(new_news["id"]) is None:
        raise Exception("Unable to find entry to update!")
    if len(new_news["title"]) == 0:
        raise Exception("Please provide a title!")
    if len(new_news["body"]) == 0:
        raise Exception("Please provide a body!")

    news = g.data.local.network.get_news(new_news["id"])
    news.title = new_news["title"]
    news.body = new_news["body"]
    g.data.local.network.put_news(news)

    return {
        "news": [format_news(news) for news in g.data.local.network.get_all_news()],
    }


@admin_pages.route("/gamesettings/update", methods=["POST"])
@jsonify
@adminrequired
def updatesettings() -> Dict[str, Any]:
    # Cast the ID for type safety.
    arcadeid = g.data.local.machine.DEFAULT_SETTINGS_ARCADE

    game = GameConstants(request.get_json()["game"])
    version = request.get_json()["version"]

    for setting_type, update_function in [
        ("bools", "replace_bool"),
        ("ints", "replace_int"),
        ("strs", "replace_str"),
        ("longstrs", "replace_str"),
    ]:
        for game_setting in request.get_json()[setting_type]:
            # Grab the value to update
            category = game_setting["category"]
            setting = game_setting["setting"]
            new_value = game_setting["value"]

            # Update the value
            current_settings = g.data.local.machine.get_settings(arcadeid, game, version, category)
            if current_settings is None:
                current_settings = ValidatedDict()

            getattr(current_settings, update_function)(setting, new_value)

            # Save it back
            g.data.local.machine.put_settings(arcadeid, game, version, category, current_settings)

    # Return the updated value
    return {
        "game_settings": [
            gs for gs in get_game_settings(g.data, arcadeid) if gs["game"] == game.value and gs["version"] == version
        ][0],
    }
