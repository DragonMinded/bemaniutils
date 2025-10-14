import copy
import json
import traceback
from typing import Any, Callable, Dict, List
from flask import Flask, abort, request, Response
from functools import wraps

from bemani.api.exceptions import APIException
from bemani.api.objects import (
    RecordsObject,
    ProfileObject,
    StatisticsObject,
    CatalogObject,
)
from bemani.api.types import g
from bemani.common import GameConstants, APIConstants, VersionConstants
from bemani.data import Config, Data

app = Flask(__name__)
config = Config()

SUPPORTED_VERSIONS: List[str] = ["v1"]


def jsonify_response(data: Dict[str, Any], code: int = 200) -> Response:
    return Response(
        json.dumps(data).encode("utf8"),
        content_type="application/json; charset=utf-8",
        status=code,
    )


@app.before_request
def before_request() -> None:
    g.config = config
    g.data = Data(config)
    g.authorized = False

    authkey = request.headers.get("Authorization")
    if authkey is not None:
        try:
            authtype, authtoken = authkey.split(" ", 1)
        except ValueError:
            authtype = None
            authtoken = None

        if authtype is not None and authtoken is not None and authtype.lower() == "token":
            g.authorized = g.data.local.api.validate_client(authtoken)


@app.after_request
def after_request(response: Response) -> Response:
    # Make sure our REST responses don't get cached, so that remote
    # servers which respect cache headers don't get confused.
    response.cache_control.no_cache = True
    response.cache_control.must_revalidate = True
    response.cache_control.private = True
    return response


@app.teardown_request
def teardown_request(exception: Any) -> None:
    data = getattr(g, "data", None)
    if data is not None:
        data.close()


def authrequired(func: Callable) -> Callable:
    @wraps(func)
    def decoratedfunction(*args: Any, **kwargs: Any) -> Response:
        if not g.authorized:
            return jsonify_response(
                {"error": "Unauthorized client!"},
                401,
            )
        else:
            return func(*args, **kwargs)

    return decoratedfunction


def jsonify(func: Callable) -> Callable:
    @wraps(func)
    def decoratedfunction(*args: Any, **kwargs: Any) -> Response:
        return jsonify_response(func(*args, **kwargs))

    return decoratedfunction


@app.errorhandler(Exception)
def server_exception(exception: Any) -> Response:
    stack = "".join(traceback.format_exception(type(exception), exception, exception.__traceback__))
    print(stack)
    try:
        g.data.local.network.put_event(
            "exception",
            {
                "service": "api",
                "request": request.url,
                "traceback": stack,
            },
        )
    except Exception:
        pass

    return jsonify_response(
        {"error": "Exception occured while processing request."},
        500,
    )


@app.errorhandler(APIException)
def api_exception(exception: Any) -> Response:
    return jsonify_response(
        {"error": exception.message},
        exception.code,
    )


@app.errorhandler(500)
def server_error(error: Any) -> Response:
    return jsonify_response(
        {"error": "Exception occured while processing request."},
        500,
    )


@app.errorhandler(501)
def protocol_error(error: Any) -> Response:
    return jsonify_response(
        {"error": "Unsupported protocol version in request."},
        501,
    )


@app.errorhandler(400)
def bad_json(error: Any) -> Response:
    return jsonify_response(
        {"error": "Request JSON could not be decoded."},
        500,
    )


@app.errorhandler(404)
def unrecognized_object(error: Any) -> Response:
    return jsonify_response(
        {"error": "Unrecognized request game/version or object."},
        404,
    )


@app.errorhandler(405)
def invalid_request(error: Any) -> Response:
    return jsonify_response(
        {"error": "Invalid request URI or method."},
        405,
    )


@app.route("/<path:path>", methods=["GET", "POST"])
@authrequired
def catch_all(path: str) -> Response:
    abort(405)


@app.route("/", methods=["GET", "POST"])
@authrequired
@jsonify
def info() -> Dict[str, Any]:
    requestdata = request.get_json()
    if requestdata is None:
        raise APIException("Request JSON could not be decoded.")
    if requestdata:
        raise APIException("Unrecognized parameters for request.")

    return {
        "versions": SUPPORTED_VERSIONS,
        "name": g.config.name,
        "email": g.config.email,
    }


@app.route("/<protoversion>/<requestgame>/<requestversion>", methods=["GET", "POST"])
@authrequired
@jsonify
def lookup(protoversion: str, requestgame: str, requestversion: str) -> Dict[str, Any]:
    requestdata = request.get_json()
    for expected in ["type", "ids", "objects"]:
        if expected not in requestdata:
            raise APIException("Missing parameters for request.")
    for param in requestdata:
        if param not in ["type", "ids", "objects", "since", "until"]:
            raise APIException("Unrecognized parameters for request.")

    args = copy.deepcopy(requestdata)
    del args["type"]
    del args["ids"]
    del args["objects"]

    if protoversion not in SUPPORTED_VERSIONS:
        # Don't know about this protocol version
        abort(501)

    # Figure out what games we support based on config, and map those.
    gamemapping = {}
    for gameid, constant in [
        ("ddr", GameConstants.DDR),
        ("iidx", GameConstants.IIDX),
        ("jubeat", GameConstants.JUBEAT),
        ("museca", GameConstants.MUSECA),
        ("popnmusic", GameConstants.POPN_MUSIC),
        ("reflecbeat", GameConstants.REFLEC_BEAT),
        ("soundvoltex", GameConstants.SDVX),
        ("danceevolution", GameConstants.DANCE_EVOLUTION),
    ]:
        if constant in g.config.support:
            gamemapping[gameid] = constant
    game = gamemapping.get(requestgame)
    if game is None:
        # Don't support this game!
        abort(404)

    if requestversion[0] == "o":
        omnimix = True
        requestversion = requestversion[1:]
    else:
        omnimix = False

    version = (
        {
            GameConstants.DDR: {
                "12": VersionConstants.DDR_X2,
                "13": VersionConstants.DDR_X3_VS_2NDMIX,
                "14": VersionConstants.DDR_2013,
                "15": VersionConstants.DDR_2014,
                "16": VersionConstants.DDR_ACE,
                "17": VersionConstants.DDR_A20,
            },
            GameConstants.IIDX: {
                "20": VersionConstants.IIDX_TRICORO,
                "21": VersionConstants.IIDX_SPADA,
                "22": VersionConstants.IIDX_PENDUAL,
                "23": VersionConstants.IIDX_COPULA,
                "24": VersionConstants.IIDX_SINOBUZ,
                "25": VersionConstants.IIDX_CANNON_BALLERS,
                "26": VersionConstants.IIDX_ROOTAGE,
                "27": VersionConstants.IIDX_HEROIC_VERSE,
                "28": VersionConstants.IIDX_BISTROVER,
            },
            GameConstants.JUBEAT: {
                "5": VersionConstants.JUBEAT_SAUCER,
                "5a": VersionConstants.JUBEAT_SAUCER_FULFILL,
                "6": VersionConstants.JUBEAT_PROP,
                "7": VersionConstants.JUBEAT_QUBELL,
                "8": VersionConstants.JUBEAT_CLAN,
                "9": VersionConstants.JUBEAT_FESTO,
                "10": VersionConstants.JUBEAT_AVENUE,
            },
            GameConstants.MUSECA: {
                "1": VersionConstants.MUSECA,
                "1p": VersionConstants.MUSECA_1_PLUS,
            },
            GameConstants.POPN_MUSIC: {
                "19": VersionConstants.POPN_MUSIC_TUNE_STREET,
                "20": VersionConstants.POPN_MUSIC_FANTASIA,
                "21": VersionConstants.POPN_MUSIC_SUNNY_PARK,
                "22": VersionConstants.POPN_MUSIC_LAPISTORIA,
                "23": VersionConstants.POPN_MUSIC_ECLALE,
                "24": VersionConstants.POPN_MUSIC_USANEKO,
                "25": VersionConstants.POPN_MUSIC_PEACE,
                "26": VersionConstants.POPN_MUSIC_KAIMEI_RIDDLES,
                "27": VersionConstants.POPN_MUSIC_UNILAB,
            },
            GameConstants.REFLEC_BEAT: {
                "1": VersionConstants.REFLEC_BEAT,
                "2": VersionConstants.REFLEC_BEAT_LIMELIGHT,
                # We don't support non-final COLETTE, so just return scores for
                # final colette to any network that asks.
                "3w": VersionConstants.REFLEC_BEAT_COLETTE,
                "3sp": VersionConstants.REFLEC_BEAT_COLETTE,
                "3su": VersionConstants.REFLEC_BEAT_COLETTE,
                "3a": VersionConstants.REFLEC_BEAT_COLETTE,
                "3as": VersionConstants.REFLEC_BEAT_COLETTE,
                # We don't support groovin'!!, so just return upper scores.
                "4": VersionConstants.REFLEC_BEAT_GROOVIN,
                "4u": VersionConstants.REFLEC_BEAT_GROOVIN,
                "5": VersionConstants.REFLEC_BEAT_VOLZZA,
                "5a": VersionConstants.REFLEC_BEAT_VOLZZA_2,
                "6": VersionConstants.REFLEC_BEAT_REFLESIA,
            },
            GameConstants.SDVX: {
                "1": VersionConstants.SDVX_BOOTH,
                "2": VersionConstants.SDVX_INFINITE_INFECTION,
                "3": VersionConstants.SDVX_GRAVITY_WARS,
                "4": VersionConstants.SDVX_HEAVENLY_HAVEN,
            },
            GameConstants.DANCE_EVOLUTION: {
                "1": VersionConstants.DANCE_EVOLUTION,
            },
        }
        .get(game, {})
        .get(requestversion)
    )
    if version is None:
        # Don't support this version!
        abort(404)

    # Attempt to coerce ID type. If we fail, provide the correct failure message.
    idtype = None
    try:
        idtype = APIConstants(requestdata["type"])
    except ValueError:
        pass
    if idtype is None:
        raise APIException("Invalid ID type provided!")

    # Validate the provided IDs given the ID type above.
    ids = requestdata["ids"]
    if idtype == APIConstants.ID_TYPE_CARD and len(ids) == 0:
        raise APIException("Invalid number of IDs given!")
    if idtype == APIConstants.ID_TYPE_SONG and len(ids) not in [1, 2]:
        raise APIException("Invalid number of IDs given!")
    if idtype == APIConstants.ID_TYPE_INSTANCE and len(ids) != 3:
        raise APIException("Invalid number of IDs given!")
    if idtype == APIConstants.ID_TYPE_SERVER and len(ids) != 0:
        raise APIException("Invalid number of IDs given!")

    responsedata = {}
    for obj in requestdata["objects"]:
        handler = {
            "records": RecordsObject,
            "profile": ProfileObject,
            "statistics": StatisticsObject,
            "catalog": CatalogObject,
        }.get(obj)
        if handler is None:
            # Don't support this object type
            abort(404)

        inst = handler(g.data, game, version, omnimix)
        try:
            fetchmethod = getattr(inst, f"fetch_{protoversion}")
        except AttributeError:
            # Don't know how to handle this object for this version
            abort(501)

        responsedata[obj] = fetchmethod(idtype, ids, args)

    return responsedata
