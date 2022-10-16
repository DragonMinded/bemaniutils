import random
from typing import Any, Dict, Optional
from flask import Blueprint, request, Response, abort, url_for

from bemani.backend.base import Base
from bemani.common import (
    CardCipher,
    CardCipherException,
    ValidatedDict,
    GameConstants,
    RegionConstants,
)
from bemani.data import Arcade, ArcadeID, Event, Machine
from bemani.frontend.app import loginrequired, jsonify, render_react, valid_pin
from bemani.frontend.gamesettings import get_game_settings
from bemani.frontend.templates import templates_location
from bemani.frontend.static import static_location
from bemani.frontend.types import g


arcade_pages = Blueprint(
    "arcade_pages",
    __name__,
    url_prefix="/arcade",
    template_folder=templates_location,
    static_folder=static_location,
)


def is_user_editable(machine: Machine) -> bool:
    return machine.game is None


def format_machine(machine: Machine) -> Dict[str, Any]:
    if machine.game is None:
        game = "any game"
    elif machine.version is None:
        game = {
            GameConstants.BISHI_BASHI: "BishiBashi",
            GameConstants.DDR: "DDR",
            GameConstants.IIDX: "IIDX",
            GameConstants.JUBEAT: "Jubeat",
            GameConstants.MGA: "Metal Gear Arcade",
            GameConstants.MUSECA: "MÚSECA",
            GameConstants.POPN_MUSIC: "Pop'n Music",
            GameConstants.REFLEC_BEAT: "Reflec Beat",
            GameConstants.SDVX: "SDVX",
        }.get(machine.game)
    elif machine.version > 0:
        game = [
            name
            for (game, version, name) in Base.all_games()
            if game == machine.game and version == machine.version
        ][0]
    elif machine.version < 0:
        game = [
            name
            for (game, version, name) in Base.all_games()
            if game == machine.game and version == -machine.version
        ][0] + " or older"

    return {
        "pcbid": machine.pcbid,
        "name": machine.name,
        "description": machine.description,
        "port": machine.port,
        "game": game,
        "editable": is_user_editable(machine),
    }


def format_arcade(arcade: Arcade) -> Dict[str, Any]:
    return {
        "id": arcade.id,
        "name": arcade.name,
        "description": arcade.description,
        "pin": arcade.pin,
        "region": arcade.region,
        "area": arcade.area,
        "paseli_enabled": arcade.data.get_bool("paseli_enabled"),
        "paseli_infinite": arcade.data.get_bool("paseli_infinite"),
        "mask_services_url": arcade.data.get_bool("mask_services_url"),
        "owners": arcade.owners,
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


@arcade_pages.route("/<int:arcadeid>")
@loginrequired
def viewarcade(arcadeid: int) -> Response:
    # Cast the ID for type safety.
    arcadeid = ArcadeID(arcadeid)

    arcade = g.data.local.machine.get_arcade(arcadeid)
    if arcade is None or g.userID not in arcade.owners:
        abort(403)
    machines = [
        format_machine(machine)
        for machine in g.data.local.machine.get_all_machines(arcade.id)
    ]
    return render_react(
        arcade.name,
        "arcade/arcade.react.js",
        {
            "arcade": format_arcade(arcade),
            "regions": RegionConstants.LUT,
            "machines": machines,
            "game_settings": get_game_settings(g.data, arcadeid),
            "balances": {
                balance[0]: balance[1]
                for balance in g.data.local.machine.get_balances(arcadeid)
            },
            "users": {
                user.id: user.username for user in g.data.local.user.get_all_users()
            },
            "events": [
                format_event(event)
                for event in g.data.local.network.get_events(
                    arcadeid=arcadeid, event="paseli_transaction"
                )
            ],
            "enforcing": g.config.server.enforce_pcbid,
            "max_pcbids": g.config.server.pcbid_self_grant_limit,
        },
        {
            "refresh": url_for("arcade_pages.listarcade", arcadeid=arcadeid),
            "paseli_enabled": url_for(
                "arcade_pages.updatearcade",
                arcadeid=arcadeid,
                attribute="paseli_enabled",
            ),
            "paseli_infinite": url_for(
                "arcade_pages.updatearcade",
                arcadeid=arcadeid,
                attribute="paseli_infinite",
            ),
            "mask_services_url": url_for(
                "arcade_pages.updatearcade",
                arcadeid=arcadeid,
                attribute="mask_services_url",
            ),
            "update_settings": url_for(
                "arcade_pages.updatesettings", arcadeid=arcadeid
            ),
            "add_balance": url_for("arcade_pages.addbalance", arcadeid=arcadeid),
            "update_balance": url_for("arcade_pages.updatebalance", arcadeid=arcadeid),
            "update_pin": url_for("arcade_pages.updatepin", arcadeid=arcadeid),
            "update_region": url_for("arcade_pages.updateregion", arcadeid=arcadeid),
            "update_area": url_for("arcade_pages.updatearea", arcadeid=arcadeid),
            "generatepcbid": url_for("arcade_pages.generatepcbid", arcadeid=arcadeid),
            "updatepcbid": url_for("arcade_pages.updatepcbid", arcadeid=arcadeid),
            "removepcbid": url_for("arcade_pages.removepcbid", arcadeid=arcadeid),
        },
    )


@arcade_pages.route("/<int:arcadeid>/list")
@jsonify
@loginrequired
def listarcade(arcadeid: int) -> Dict[str, Any]:
    # Cast the ID for type safety.
    arcadeid = ArcadeID(arcadeid)

    # Make sure the arcade is valid
    arcade = g.data.local.machine.get_arcade(arcadeid)
    if arcade is None or g.userID not in arcade.owners:
        raise Exception("You don't own this arcade, refusing to list!")

    machines = [
        format_machine(machine)
        for machine in g.data.local.machine.get_all_machines(arcade.id)
    ]
    return {
        "machines": machines,
        "balances": {
            balance[0]: balance[1]
            for balance in g.data.local.machine.get_balances(arcadeid)
        },
        "users": {user.id: user.username for user in g.data.local.user.get_all_users()},
        "events": [
            format_event(event)
            for event in g.data.local.network.get_events(
                arcadeid=arcadeid, event="paseli_transaction"
            )
        ],
    }


@arcade_pages.route("/<int:arcadeid>/balance/add", methods=["POST"])
@jsonify
@loginrequired
def addbalance(arcadeid: int) -> Dict[str, Any]:
    # Cast the ID for type safety.
    arcadeid = ArcadeID(arcadeid)
    credits = request.get_json()["credits"]
    card = request.get_json()["card"]

    # Make sure the arcade is valid
    arcade = g.data.local.machine.get_arcade(arcadeid)
    if arcade is None or g.userID not in arcade.owners:
        raise Exception("You don't own this arcade, refusing to update!")

    try:
        cardid = CardCipher.decode(card)
        userid = g.data.local.user.from_cardid(cardid)
    except CardCipherException:
        userid = None

    if userid is None:
        raise Exception("Unable to find user by this card!")

    # Update balance
    balance = g.data.local.user.update_balance(userid, arcadeid, credits)
    if balance is not None:
        g.data.local.network.put_event(
            "paseli_transaction",
            {
                "delta": credits,
                "balance": balance,
                "reason": "arcade operator adjustment",
            },
            userid=userid,
            arcadeid=arcadeid,
        )

    return {
        "balances": {
            balance[0]: balance[1]
            for balance in g.data.local.machine.get_balances(arcadeid)
        },
        "users": {user.id: user.username for user in g.data.local.user.get_all_users()},
        "events": [
            format_event(event)
            for event in g.data.local.network.get_events(
                arcadeid=arcadeid, event="paseli_transaction"
            )
        ],
    }


@arcade_pages.route("/<int:arcadeid>/balance/update", methods=["POST"])
@jsonify
@loginrequired
def updatebalance(arcadeid: int) -> Dict[str, Any]:
    # Cast the ID for type safety.
    arcadeid = ArcadeID(arcadeid)
    credits = request.get_json()["credits"]

    # Make sure the arcade is valid
    arcade = g.data.local.machine.get_arcade(arcadeid)
    if arcade is None or g.userID not in arcade.owners:
        raise Exception("You don't own this arcade, refusing to update!")

    # Update balances
    for userid in credits:
        balance = g.data.local.user.update_balance(userid, arcadeid, credits[userid])
        if balance is not None:
            g.data.local.network.put_event(
                "paseli_transaction",
                {
                    "delta": credits[userid],
                    "balance": balance,
                    "reason": "arcade operator adjustment",
                },
                userid=userid,
                arcadeid=arcadeid,
            )

    return {
        "balances": {
            balance[0]: balance[1]
            for balance in g.data.local.machine.get_balances(arcadeid)
        },
        "users": {user.id: user.username for user in g.data.local.user.get_all_users()},
        "events": [
            format_event(event)
            for event in g.data.local.network.get_events(
                arcadeid=arcadeid, event="paseli_transaction"
            )
        ],
    }


@arcade_pages.route("/<int:arcadeid>/pin/update", methods=["POST"])
@jsonify
@loginrequired
def updatepin(arcadeid: int) -> Dict[str, Any]:
    # Cast the ID for type safety.
    arcadeid = ArcadeID(arcadeid)

    pin = request.get_json()["pin"]

    # Make sure the arcade is valid
    arcade = g.data.local.machine.get_arcade(arcadeid)
    if arcade is None or g.userID not in arcade.owners:
        raise Exception("You don't own this arcade, refusing to update!")

    if not valid_pin(pin, "arcade"):
        raise Exception("Invalid PIN, must be exactly 8 digits!")

    # Update and save
    arcade.pin = pin
    g.data.local.machine.put_arcade(arcade)

    # Return nothing
    return {"pin": pin}


@arcade_pages.route("/<int:arcadeid>/region/update", methods=["POST"])
@jsonify
@loginrequired
def updateregion(arcadeid: int) -> Dict[str, Any]:
    # Cast the ID for type safety.
    arcadeid = ArcadeID(arcadeid)

    try:
        region = int(request.get_json()["region"])
    except Exception:
        region = 0

    # Make sure the arcade is valid
    arcade = g.data.local.machine.get_arcade(arcadeid)
    if arcade is None or g.userID not in arcade.owners:
        raise Exception("You don't own this arcade, refusing to update!")

    if region not in {RegionConstants.EUROPE, RegionConstants.NO_MAPPING} and (
        region < RegionConstants.MIN or region > RegionConstants.MAX
    ):
        raise Exception("Invalid region!")

    # Update and save
    arcade.region = region
    g.data.local.machine.put_arcade(arcade)

    # Return nothing
    return {"region": region}


@arcade_pages.route("/<int:arcadeid>/area/update", methods=["POST"])
@jsonify
@loginrequired
def updatearea(arcadeid: int) -> Dict[str, Any]:
    # Cast the ID for type safety.
    arcadeid = ArcadeID(arcadeid)

    try:
        area = request.get_json()["area"] or None
    except Exception:
        area = None

    # Make sure the arcade is valid
    arcade = g.data.local.machine.get_arcade(arcadeid)
    if arcade is None or g.userID not in arcade.owners:
        raise Exception("You don't own this arcade, refusing to update!")

    # Update and save
    arcade.area = area
    g.data.local.machine.put_arcade(arcade)

    # Return nothing
    return {"area": area}


@arcade_pages.route("/<int:arcadeid>/pcbids/generate", methods=["POST"])
@jsonify
@loginrequired
def generatepcbid(arcadeid: int) -> Dict[str, Any]:
    # Cast the ID for type safety.
    arcadeid = ArcadeID(arcadeid)

    # Make sure that arcade owners are allowed to generate PCBIDs in the first place.
    if g.config.server.pcbid_self_grant_limit <= 0:
        raise Exception("You don't have permission to generate PCBIDs!")

    # Make sure the arcade is valid and the current user has permissions to
    # modify it.
    arcade = g.data.local.machine.get_arcade(arcadeid)
    if arcade is None or g.userID not in arcade.owners:
        raise Exception("You don't own this arcade, refusing to update!")

    # Make sure the user hasn't gone over their limit of PCBIDs.
    existing_machine_count = len(
        [
            machine
            for machine in g.data.local.machine.get_all_machines(arcade.id)
            if is_user_editable(machine)
        ]
    )
    if existing_machine_count >= g.config.server.pcbid_self_grant_limit:
        raise Exception("You have hit your limit of allowed PCBIDs!")

    # Will be set by the game on boot.
    name: str = "なし"
    pcbid: Optional[str] = None
    new_machine = request.get_json()["machine"]

    while pcbid is None:
        # Generate a new PCBID, check for uniqueness
        potential_pcbid = "01201000000000" + "".join(
            [random.choice("0123456789ABCDEF") for _ in range(6)]
        )
        if g.data.local.machine.get_machine(potential_pcbid) is None:
            pcbid = potential_pcbid

    # Finally, add the generated PCBID to the network.
    g.data.local.machine.create_machine(
        pcbid, name, new_machine["description"], arcade.id
    )

    # Just return all machines for ease of updating
    return {
        "machines": [
            format_machine(machine)
            for machine in g.data.local.machine.get_all_machines(arcade.id)
        ],
    }


@arcade_pages.route("/<int:arcadeid>/pcbids/update", methods=["POST"])
@jsonify
@loginrequired
def updatepcbid(arcadeid: int) -> Dict[str, Any]:
    # Cast the ID for type safety.
    arcadeid = ArcadeID(arcadeid)

    # Make sure that arcade owners are allowed to edit PCBIDs in the first place.
    if g.config.server.pcbid_self_grant_limit <= 0:
        raise Exception("You don't have permission to edit PCBIDs!")

    # Make sure the arcade is valid and the current user has permissions to
    # modify it.
    arcade = g.data.local.machine.get_arcade(arcadeid)
    if arcade is None or g.userID not in arcade.owners:
        raise Exception("You don't own this arcade, refusing to update!")

    # Grab the new updates as well as the old values to validate editing permissions.
    updated_machine = request.get_json()["machine"]
    current_machine = g.data.local.machine.get_machine(updated_machine["pcbid"])

    # Make sure the PCBID we are trying to modify is actually owned by this arcade.
    # Also, make sure that the PCBID is actually user-editable.
    if (
        current_machine is None
        or current_machine.arcade != arcadeid
        or not is_user_editable(current_machine)
    ):
        raise Exception("You don't own this PCBID, refusing to update!")

    # Make sure the port is actually valid.
    try:
        port = int(updated_machine["port"])
    except ValueError:
        port = None
    if port is None:
        raise Exception("The specified port is invalid!")
    if port < 1 or port > 65535:
        raise Exception("The specified port is out of range!")

    # Make sure we don't duplicate port assignments.
    other_pcbid = g.data.local.machine.from_port(port)
    if other_pcbid is not None and other_pcbid != updated_machine["pcbid"]:
        raise Exception("The specified port is already in use!")

    # Update the allowed bits of data.
    current_machine.description = updated_machine["description"]
    current_machine.port = port
    g.data.local.machine.put_machine(current_machine)

    # Just return all machines for ease of updating
    return {
        "machines": [
            format_machine(machine)
            for machine in g.data.local.machine.get_all_machines(arcade.id)
        ],
    }


@arcade_pages.route("/<int:arcadeid>/pcbids/remove", methods=["POST"])
@jsonify
@loginrequired
def removepcbid(arcadeid: int) -> Dict[str, Any]:
    # Cast the ID for type safety.
    arcadeid = ArcadeID(arcadeid)

    # Make sure that arcade owners are allowed to edit PCBIDs in the first place.
    if g.config.server.pcbid_self_grant_limit <= 0:
        raise Exception("You don't have permission to edit PCBIDs!")

    # Make sure the arcade is valid and the current user has permissions to
    # modify it.
    arcade = g.data.local.machine.get_arcade(arcadeid)
    if arcade is None or g.userID not in arcade.owners:
        raise Exception("You don't own this arcade, refusing to update!")

    # Attempt to look the PCBID we are deleting up to ensure it exists.
    pcbid = request.get_json()["pcbid"]

    # Make sure the PCBID we are trying to delete is actually owned by this arcade.
    # Also, make sure that the PCBID is actually user-editable.
    machine = g.data.local.machine.get_machine(pcbid)
    if machine is None or machine.arcade != arcadeid or not is_user_editable(machine):
        raise Exception("You don't own this PCBID, refusing to update!")

    # Actually delete it.
    g.data.local.machine.destroy_machine(pcbid)

    # Just return all machines for ease of updating
    return {
        "machines": [
            format_machine(machine)
            for machine in g.data.local.machine.get_all_machines(arcade.id)
        ],
    }


@arcade_pages.route("/<int:arcadeid>/update/<string:attribute>", methods=["POST"])
@jsonify
@loginrequired
def updatearcade(arcadeid: int, attribute: str) -> Dict[str, Any]:
    # Cast the ID for type safety.
    arcadeid = ArcadeID(arcadeid)

    # Attempt to look this arcade up
    new_value = request.get_json()["value"]
    arcade = g.data.local.machine.get_arcade(arcadeid)
    if arcade is None or g.userID not in arcade.owners:
        raise Exception("You don't own this arcade, refusing to update!")

    if attribute == "paseli_enabled":
        arcade.data.replace_bool("paseli_enabled", new_value)
    elif attribute == "paseli_infinite":
        arcade.data.replace_bool("paseli_infinite", new_value)
    elif attribute == "mask_services_url":
        arcade.data.replace_bool("mask_services_url", new_value)
    else:
        raise Exception(f"Unknown attribute {attribute} to update!")

    g.data.local.machine.put_arcade(arcade)

    # Return the updated value
    return {
        "value": new_value,
    }


@arcade_pages.route("/<int:arcadeid>/settings/update", methods=["POST"])
@jsonify
@loginrequired
def updatesettings(arcadeid: int) -> Dict[str, Any]:
    # Cast the ID for type safety.
    arcadeid = ArcadeID(arcadeid)

    # Attempt to look this arcade up
    arcade = g.data.local.machine.get_arcade(arcadeid)
    if arcade is None or g.userID not in arcade.owners:
        raise Exception("You don't own this arcade, refusing to update!")

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
            current_settings = g.data.local.machine.get_settings(
                arcadeid, game, version, category
            )
            if current_settings is None:
                current_settings = ValidatedDict()

            getattr(current_settings, update_function)(setting, new_value)

            # Save it back
            g.data.local.machine.put_settings(
                arcade.id, game, version, category, current_settings
            )

    # Return the updated value
    return {
        "game_settings": [
            gs
            for gs in get_game_settings(g.data, arcadeid)
            if gs["game"] == game.value and gs["version"] == version
        ][0],
    }
