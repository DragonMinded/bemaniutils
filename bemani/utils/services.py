import argparse
import copy
import traceback
import yaml
from typing import Any, Dict
from flask import Flask, request, redirect, Response, make_response

from bemani.protocol import EAmuseProtocol
from bemani.backend import Dispatch, UnrecognizedPCBIDException
from bemani.backend.iidx import IIDXFactory
from bemani.backend.popn import PopnMusicFactory
from bemani.backend.jubeat import JubeatFactory
from bemani.backend.bishi import BishiBashiFactory
from bemani.backend.ddr import DDRFactory
from bemani.backend.sdvx import SoundVoltexFactory
from bemani.backend.reflec import ReflecBeatFactory
from bemani.backend.museca import MusecaFactory
from bemani.common import GameConstants
from bemani.data import Data


app = Flask(__name__)
config: Dict[str, Any] = {}


@app.route('/', defaults={'path': ''}, methods=['GET'])
@app.route('/<path:path>', methods=['GET'])
def receive_healthcheck(path: str) -> Response:
    global config
    redirect_uri = config['server'].get('redirect')
    if redirect_uri is None:
        # Return a standard status OKAY message.
        return Response("Services OK.")
    else:
        # Redirect to the configured location.
        return redirect(redirect_uri, code=308)  # type: ignore


@app.route('/', defaults={'path': ''}, methods=['POST'])
@app.route('/<path:path>', methods=['POST'])
def receive_request(path: str) -> Response:
    proto = EAmuseProtocol()
    remote_address = request.headers.get('x-remote-address', None)
    compression = request.headers.get('x-compress', None)
    encryption = request.headers.get('x-eamuse-info', None)
    req = proto.decode(
        compression,
        encryption,
        request.data,
    )

    if req is None:
        # Nothing to do here
        return Response("Unrecognized packet!", 500)
    if req.name in {'soapenv:Envelope', 'soap:Envelope', 'methodCall'}:
        # We get lots of spam from random bots trying to SOAP
        # us up, so ignore this shit.
        return Response("Unrecognized packet!", 500)

    # Create and format config
    global config
    requestconfig = copy.copy(config)
    requestconfig['client'] = {
        'address': remote_address or request.remote_addr,
    }

    dataprovider = Data(requestconfig)
    try:
        dispatch = Dispatch(requestconfig, dataprovider, True)
        resp = dispatch.handle(req)

        if resp is None:
            # Nothing to do here
            dataprovider.local.network.put_event(
                'unhandled_packet',
                {
                    'request': str(req),
                },
            )
            return Response("No response generated", 404)

        compression = None

        data = proto.encode(
            compression,
            encryption,
            resp,
        )

        response = make_response(data)

        # Some old clients are case-sensitive, even though http spec says these
        # shouldn't matter, so capitalize correctly.
        if compression:
            response.headers['X-Compress'] = compression
        else:
            response.headers['X-Compress'] = 'none'
        if encryption:
            response.headers['X-Eamuse-Info'] = encryption

        return response
    except UnrecognizedPCBIDException as e:
        dataprovider.local.network.put_event(
            'unauthorized_pcbid',
            {
                'pcbid': e.pcbid,
                'model': e.model,
                'ip': e.ip,
            },
        )
        return Response("Unauthorized client", 403)
    except Exception:
        stack = traceback.format_exc()
        print(stack)
        dataprovider.local.network.put_event(
            'exception',
            {
                'service': 'xrpc',
                'request': str(req),
                'traceback': stack,
            },
        )
        return Response("Crash when handling packet!", 500)
    finally:
        dataprovider.close()


def load_config(filename: str) -> None:
    global config

    config.update(yaml.safe_load(open(filename)))
    config['database']['engine'] = Data.create_engine(config)


def register_games() -> None:
    global config

    if config.get('support', {}).get(GameConstants.POPN_MUSIC, False):
        PopnMusicFactory.register_all()
    if config.get('support', {}).get(GameConstants.JUBEAT, False):
        JubeatFactory.register_all()
    if config.get('support', {}).get(GameConstants.IIDX, False):
        IIDXFactory.register_all()
    if config.get('support', {}).get(GameConstants.BISHI_BASHI, False):
        BishiBashiFactory.register_all()
    if config.get('support', {}).get(GameConstants.DDR, False):
        DDRFactory.register_all()
    if config.get('support', {}).get(GameConstants.REFLEC_BEAT, False):
        ReflecBeatFactory.register_all()
    if config.get('support', {}).get(GameConstants.SDVX, False):
        SoundVoltexFactory.register_all()
    if config.get('support', {}).get(GameConstants.MUSECA, False):
        MusecaFactory.register_all()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="A backend services provider for eAmusement games")
    parser.add_argument("-p", "--port", help="Port to listen on. Defaults to 80", type=int, default=80)
    parser.add_argument("-c", "--config", help="Core configuration. Defaults to server.yaml", type=str, default="server.yaml")
    parser.add_argument("-r", "--profile", help="Turn on profiling for front end", action="store_true")
    args = parser.parse_args()

    # Set up global configuration, overriding config port for convenience
    load_config(args.config)
    config['server']['port'] = args.port

    # Register game handlers
    register_games()

    if args.profile:
        from werkzeug.contrib.profiler import ProfilerMiddleware
        app.wsgi_app = ProfilerMiddleware(app.wsgi_app, profile_dir='.')  # type: ignore

    # Run the app
    app.run(host='0.0.0.0', port=args.port, debug=True)
