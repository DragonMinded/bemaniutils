import argparse
import yaml

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
from bemani.frontend import app, config  # noqa: F401
from bemani.frontend.account import account_pages
from bemani.frontend.admin import admin_pages
from bemani.frontend.arcade import arcade_pages
from bemani.frontend.home import home_pages
from bemani.frontend.iidx import iidx_pages
from bemani.frontend.popn import popn_pages
from bemani.frontend.bishi import bishi_pages
from bemani.frontend.jubeat import jubeat_pages
from bemani.frontend.ddr import ddr_pages
from bemani.frontend.sdvx import sdvx_pages
from bemani.frontend.reflec import reflec_pages
from bemani.frontend.museca import museca_pages


def register_blueprints() -> None:
    global config

    app.register_blueprint(account_pages)
    app.register_blueprint(admin_pages)
    app.register_blueprint(arcade_pages)
    app.register_blueprint(home_pages)

    if config.get('support', {}).get(GameConstants.IIDX, False):
        app.register_blueprint(iidx_pages)
    if config.get('support', {}).get(GameConstants.POPN_MUSIC, False):
        app.register_blueprint(popn_pages)
    if config.get('support', {}).get(GameConstants.JUBEAT, False):
        app.register_blueprint(jubeat_pages)
    if config.get('support', {}).get(GameConstants.BISHI_BASHI, False):
        app.register_blueprint(bishi_pages)
    if config.get('support', {}).get(GameConstants.DDR, False):
        app.register_blueprint(ddr_pages)
    if config.get('support', {}).get(GameConstants.SDVX, False):
        app.register_blueprint(sdvx_pages)
    if config.get('support', {}).get(GameConstants.REFLEC_BEAT, False):
        app.register_blueprint(reflec_pages)
    if config.get('support', {}).get(GameConstants.MUSECA, False):
        app.register_blueprint(museca_pages)


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
    if config.get('support', {}).get(GameConstants.SDVX, False):
        SoundVoltexFactory.register_all()
    if config.get('support', {}).get(GameConstants.REFLEC_BEAT, False):
        ReflecBeatFactory.register_all()
    if config.get('support', {}).get(GameConstants.MUSECA, False):
        MusecaFactory.register_all()


def load_config(filename: str) -> None:
    global config

    config.update(yaml.safe_load(open(filename)))
    config['database']['engine'] = Data.create_engine(config)
    app.secret_key = config['secret_key']


def main() -> None:
    parser = argparse.ArgumentParser(description="A front end services provider for eAmusement games.")
    parser.add_argument("-p", "--port", help="Port to listen on. Defaults to 80", type=int, default=80)
    parser.add_argument("-c", "--config", help="Core configuration. Defaults to server.yaml", type=str, default="server.yaml")
    parser.add_argument("-r", "--profile", help="Turn on profiling for front end", action="store_true")
    args = parser.parse_args()

    # Set up app
    load_config(args.config)

    # Register all blueprints
    register_blueprints()

    # Register all games
    register_games()

    if args.profile:
        from werkzeug.contrib.profiler import ProfilerMiddleware
        app.wsgi_app = ProfilerMiddleware(app.wsgi_app, profile_dir='.')  # type: ignore

    # Run the app
    app.run(host='0.0.0.0', port=args.port, debug=True)


if __name__ == '__main__':
    main()
