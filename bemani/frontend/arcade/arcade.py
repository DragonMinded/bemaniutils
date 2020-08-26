from typing import Any, Dict, List
from flask import Blueprint, request, Response, abort, url_for, g  # type: ignore

from bemani.backend.base import Base
from bemani.common import CardCipher, CardCipherException, ValidatedDict, GameConstants
from bemani.data import Arcade, Event, Machine
from bemani.frontend.app import loginrequired, jsonify, render_react, valid_pin
from bemani.frontend.templates import templates_location
from bemani.frontend.static import static_location

arcade_pages = Blueprint(
    'arcade_pages',
    __name__,
    url_prefix='/arcade',
    template_folder=templates_location,
    static_folder=static_location,
)


def format_machine(machine: Machine) -> Dict[str, Any]:
    if machine.game is None:
        game = 'any game'
    elif machine.version is None:
        game = {
            GameConstants.BISHI_BASHI: 'BishiBashi',
            GameConstants.DDR: 'DDR',
            GameConstants.IIDX: 'IIDX',
            GameConstants.JUBEAT: 'Jubeat',
            GameConstants.MUSECA: 'MÚSECA',
            GameConstants.POPN_MUSIC: 'Pop\'n Music',
            GameConstants.REFLEC_BEAT: 'Reflec Beat',
            GameConstants.SDVX: 'SDVX',
        }.get(machine.game)
    elif machine.version > 0:
        game = [
            name for (game, version, name) in Base.all_games()
            if game == machine.game and version == machine.version
        ][0]
    elif machine.version < 0:
        game = [
            name for (game, version, name) in Base.all_games()
            if game == machine.game and version == -machine.version
        ][0] + ' or older'

    return {
        'pcbid': machine.pcbid,
        'name': machine.name,
        'description': machine.description,
        'port': machine.port,
        'game': game,
    }


def format_arcade(arcade: Arcade) -> Dict[str, Any]:
    return {
        'id': arcade.id,
        'name': arcade.name,
        'description': arcade.description,
        'pin': arcade.pin,
        'paseli_enabled': arcade.data.get_bool('paseli_enabled'),
        'paseli_infinite': arcade.data.get_bool('paseli_infinite'),
        'mask_services_url': arcade.data.get_bool('mask_services_url'),
        'owners': arcade.owners,
    }


def format_event(event: Event) -> Dict[str, Any]:
    return {
        'id': event.id,
        'timestamp': event.timestamp,
        'userid': event.userid,
        'arcadeid': event.arcadeid,
        'type': event.type,
        'data': event.data,
    }


def get_game_settings(arcade: Arcade) -> List[Dict[str, Any]]:
    game_lut: Dict[str, Dict[int, str]] = {}
    settings_lut: Dict[str, Dict[int, Dict[str, Any]]] = {}
    all_settings = []

    for (game, version, name) in Base.all_games():
        if game not in game_lut:
            game_lut[game] = {}
            settings_lut[game] = {}
        game_lut[game][version] = name
        settings_lut[game][version] = {}

    for (game, version, settings) in Base.all_settings():
        if not settings:
            continue

        # First, set up the basics
        game_settings: Dict[str, Any] = {
            'game': game,
            'version': version,
            'name': game_lut[game][version],
            'bools': [],
            'ints': [],
            'strs': [],
            'longstrs': [],
        }

        # Now, look up the current setting for each returned setting
        for setting_type, setting_unpacker in [
            ('bools', "get_bool"),
            ('ints', "get_int"),
            ('strs', "get_str"),
            ('longstrs', "get_str"),
        ]:
            for setting in settings.get(setting_type, []):
                if setting['category'] not in settings_lut[game][version]:
                    cached_setting = g.data.local.machine.get_settings(arcade.id, game, version, setting['category'])
                    if cached_setting is None:
                        cached_setting = ValidatedDict()
                    settings_lut[game][version][setting['category']] = cached_setting

                current_settings = settings_lut[game][version][setting['category']]
                setting['value'] = getattr(current_settings, setting_unpacker)(setting['setting'])
                game_settings[setting_type].append(setting)

        # Now, include it!
        all_settings.append(game_settings)

    return sorted(
        all_settings,
        key=lambda setting: (setting['game'], setting['version']),
    )


@arcade_pages.route('/<int:arcadeid>')
@loginrequired
def viewarcade(arcadeid: int) -> Response:
    arcade = g.data.local.machine.get_arcade(arcadeid)
    if g.userID not in arcade.owners:
        abort(403)
    machines = [
        format_machine(machine) for machine in g.data.local.machine.get_all_machines(arcade.id)
    ]
    return render_react(
        arcade.name,
        'arcade/arcade.react.js',
        {
            'arcade': format_arcade(arcade),
            'machines': machines,
            'game_settings': get_game_settings(arcade),
            'balances': {balance[0]: balance[1] for balance in g.data.local.machine.get_balances(arcadeid)},
            'users': {user.id: user.username for user in g.data.local.user.get_all_users()},
            'events': [format_event(event) for event in g.data.local.network.get_events(arcadeid=arcadeid, event='paseli_transaction')],
            'enforcing': g.config['server']['enforce_pcbid'],
        },
        {
            'refresh': url_for('arcade_pages.listarcade', arcadeid=arcadeid),
            'viewuser': url_for('admin_pages.viewuser', userid=-1),
            'paseli_enabled': url_for('arcade_pages.updatearcade', arcadeid=arcadeid, attribute='paseli_enabled'),
            'paseli_infinite': url_for('arcade_pages.updatearcade', arcadeid=arcadeid, attribute='paseli_infinite'),
            'mask_services_url': url_for('arcade_pages.updatearcade', arcadeid=arcadeid, attribute='mask_services_url'),
            'update_settings': url_for('arcade_pages.updatesettings', arcadeid=arcadeid),
            'add_balance': url_for('arcade_pages.addbalance', arcadeid=arcadeid),
            'update_balance': url_for('arcade_pages.updatebalance', arcadeid=arcadeid),
            'update_pin': url_for('arcade_pages.updatepin', arcadeid=arcadeid),
        },
    )


@arcade_pages.route('/<int:arcadeid>/list')
@jsonify
@loginrequired
def listarcade(arcadeid: int) -> Dict[str, Any]:
    # Make sure the arcade is valid
    arcade = g.data.local.machine.get_arcade(arcadeid)
    if arcade is None:
        raise Exception('Unable to find arcade to list!')
    if g.userID not in arcade.owners:
        raise Exception('You don\'t own this arcade, refusing to list!')

    machines = [
        format_machine(machine) for machine in g.data.local.machine.get_all_machines(arcade.id)
    ]
    return {
        'machines': machines,
        'balances': {balance[0]: balance[1] for balance in g.data.local.machine.get_balances(arcadeid)},
        'users': {user.id: user.username for user in g.data.local.user.get_all_users()},
        'events': [format_event(event) for event in g.data.local.network.get_events(arcadeid=arcadeid, event='paseli_transaction')],
    }


@arcade_pages.route('/<int:arcadeid>/balance/add', methods=['POST'])
@jsonify
@loginrequired
def addbalance(arcadeid: int) -> Dict[str, Any]:
    credits = request.get_json()['credits']
    card = request.get_json()['card']

    # Make sure the arcade is valid
    arcade = g.data.local.machine.get_arcade(arcadeid)
    if arcade is None:
        raise Exception('Unable to find arcade to update!')
    if g.userID not in arcade.owners:
        raise Exception('You don\'t own this arcade, refusing to update!')

    try:
        cardid = CardCipher.decode(card)
        userid = g.data.local.user.from_cardid(cardid)
    except CardCipherException:
        userid = None

    if userid is None:
        raise Exception('Unable to find user by this card!')

    # Update balance
    balance = g.data.local.user.update_balance(userid, arcadeid, credits)
    if balance is not None:
        g.data.local.network.put_event(
            'paseli_transaction',
            {
                'delta': credits,
                'balance': balance,
                'reason': 'arcade operator adjustment',
            },
            userid=userid,
            arcadeid=arcadeid,
        )

    return {
        'balances': {balance[0]: balance[1] for balance in g.data.local.machine.get_balances(arcadeid)},
        'users': {user.id: user.username for user in g.data.local.user.get_all_users()},
        'events': [format_event(event) for event in g.data.local.network.get_events(arcadeid=arcadeid, event='paseli_transaction')],
    }


@arcade_pages.route('/<int:arcadeid>/balance/update', methods=['POST'])
@jsonify
@loginrequired
def updatebalance(arcadeid: int) -> Dict[str, Any]:
    credits = request.get_json()['credits']

    # Make sure the arcade is valid
    arcade = g.data.local.machine.get_arcade(arcadeid)
    if arcade is None:
        raise Exception('Unable to find arcade to update!')
    if g.userID not in arcade.owners:
        raise Exception('You don\'t own this arcade, refusing to update!')

    # Update balances
    for userid in credits:
        balance = g.data.local.user.update_balance(userid, arcadeid, credits[userid])
        if balance is not None:
            g.data.local.network.put_event(
                'paseli_transaction',
                {
                    'delta': credits[userid],
                    'balance': balance,
                    'reason': 'arcade operator adjustment',
                },
                userid=userid,
                arcadeid=arcadeid,
            )

    return {
        'balances': {balance[0]: balance[1] for balance in g.data.local.machine.get_balances(arcadeid)},
        'users': {user.id: user.username for user in g.data.local.user.get_all_users()},
        'events': [format_event(event) for event in g.data.local.network.get_events(arcadeid=arcadeid, event='paseli_transaction')],
    }


@arcade_pages.route('/<int:arcadeid>/pin/update', methods=['POST'])
@jsonify
@loginrequired
def updatepin(arcadeid: int) -> Dict[str, Any]:
    pin = request.get_json()['pin']

    # Make sure the arcade is valid
    arcade = g.data.local.machine.get_arcade(arcadeid)
    if arcade is None:
        raise Exception('Unable to find arcade to update!')
    if g.userID not in arcade.owners:
        raise Exception('You don\'t own this arcade, refusing to update!')

    if not valid_pin(pin, 'arcade'):
        raise Exception('Invalid PIN, must be exactly 8 digits!')

    # Update and save
    arcade.pin = pin
    g.data.local.machine.put_arcade(arcade)

    # Return nothing
    return {'pin': pin}


@arcade_pages.route('/<int:arcadeid>/update/<string:attribute>', methods=['POST'])
@jsonify
@loginrequired
def updatearcade(arcadeid: int, attribute: str) -> Dict[str, Any]:
    # Attempt to look this arcade up
    new_value = request.get_json()['value']
    arcade = g.data.local.machine.get_arcade(arcadeid)
    if arcade is None:
        raise Exception('Unable to find arcade to update!')
    if g.userID not in arcade.owners:
        raise Exception('You don\'t own this arcade, refusing to update!')

    if attribute == 'paseli_enabled':
        arcade.data.replace_bool('paseli_enabled', new_value)
    elif attribute == 'paseli_infinite':
        arcade.data.replace_bool('paseli_infinite', new_value)
    elif attribute == 'mask_services_url':
        arcade.data.replace_bool('mask_services_url', new_value)
    else:
        raise Exception(f'Unknown attribute {attribute} to update!')

    g.data.local.machine.put_arcade(arcade)

    # Return the updated value
    return {
        'value': new_value,
    }


@arcade_pages.route('/<int:arcadeid>/settings/update', methods=['POST'])
@jsonify
@loginrequired
def updatesettings(arcadeid: int) -> Dict[str, Any]:
    # Attempt to look this arcade up
    arcade = g.data.local.machine.get_arcade(arcadeid)

    if arcade is None:
        raise Exception('Unable to find arcade to update!')
    if g.userID not in arcade.owners:
        raise Exception('You don\'t own this arcade, refusing to update!')

    game = request.get_json()['game']
    version = request.get_json()['version']

    for setting_type, update_function in [
        ('bools', 'replace_bool'),
        ('ints', 'replace_int'),
        ('strs', 'replace_str'),
        ('longstrs', 'replace_str'),
    ]:
        for game_setting in request.get_json()[setting_type]:
            # Grab the value to update
            category = game_setting['category']
            setting = game_setting['setting']
            new_value = game_setting['value']

            # Update the value
            current_settings = g.data.local.machine.get_settings(arcade.id, game, version, category)
            if current_settings is None:
                current_settings = ValidatedDict()

            getattr(current_settings, update_function)(setting, new_value)

            # Save it back
            g.data.local.machine.put_settings(arcade.id, game, version, category, current_settings)

    # Return the updated value
    return {
        'game_settings': [
            gs for gs in get_game_settings(arcade)
            if gs['game'] == game and gs['version'] == version
        ][0],
    }
