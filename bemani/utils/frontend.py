import argparse
from typing import Any

from bemani.common import GameConstants
from bemani.frontend import app, config  # noqa: F401
from bemani.frontend.account import account_pages
from bemani.frontend.admin import admin_pages
from bemani.frontend.arcade import arcade_pages
from bemani.frontend.home import home_pages
from bemani.frontend.iidx import iidx_pages
from bemani.frontend.popn import popn_pages
from bemani.frontend.bishi import bishi_pages
from bemani.frontend.mga import mga_pages
from bemani.frontend.jubeat import jubeat_pages
from bemani.frontend.ddr import ddr_pages
from bemani.frontend.sdvx import sdvx_pages
from bemani.frontend.reflec import reflec_pages
from bemani.frontend.museca import museca_pages
from bemani.frontend.danevo import danevo_pages
from bemani.utils.config import (
    load_config as base_load_config,
    instantiate_cache as base_instantiate_cache,
    register_games as base_register_games,
)


def register_blueprints() -> None:
    app.register_blueprint(account_pages)
    app.register_blueprint(admin_pages)
    app.register_blueprint(arcade_pages)
    app.register_blueprint(home_pages)

    if GameConstants.IIDX in config.support:
        app.register_blueprint(iidx_pages)
    if GameConstants.POPN_MUSIC in config.support:
        app.register_blueprint(popn_pages)
    if GameConstants.JUBEAT in config.support:
        app.register_blueprint(jubeat_pages)
    if GameConstants.BISHI_BASHI in config.support:
        app.register_blueprint(bishi_pages)
    if GameConstants.MGA in config.support:
        app.register_blueprint(mga_pages)
    if GameConstants.DDR in config.support:
        app.register_blueprint(ddr_pages)
    if GameConstants.SDVX in config.support:
        app.register_blueprint(sdvx_pages)
    if GameConstants.REFLEC_BEAT in config.support:
        app.register_blueprint(reflec_pages)
    if GameConstants.MUSECA in config.support:
        app.register_blueprint(museca_pages)
    if GameConstants.DANCE_EVOLUTION in config.support:
        app.register_blueprint(danevo_pages)


def register_games() -> None:
    base_register_games(config)


def load_config(filename: str) -> None:
    base_load_config(filename, config)
    app.secret_key = config.secret_key


def instantiate_cache(app: Any) -> None:
    base_instantiate_cache(config, app)


def main() -> None:
    parser = argparse.ArgumentParser(description="A front end services provider for eAmusement games.")
    parser.add_argument("-p", "--port", help="Port to listen on. Defaults to 80", type=int, default=80)
    parser.add_argument(
        "-c",
        "--config",
        help="Core configuration. Defaults to server.yaml",
        type=str,
        default="server.yaml",
    )
    parser.add_argument(
        "-r",
        "--profile",
        help="Turn on profiling for front end, writing CProfile data to the currenct directory",
        action="store_true",
    )
    parser.add_argument(
        "-o",
        "--read-only",
        action="store_true",
        help="Force the database into read-only mode.",
    )
    args = parser.parse_args()

    # Set up app
    load_config(args.config)
    if args.read_only:
        config["database"]["read_only"] = True

    # Register all blueprints
    register_blueprints()

    # Register all games
    register_games()

    if args.profile:
        from werkzeug.middleware.profiler import ProfilerMiddleware

        app.wsgi_app = ProfilerMiddleware(app.wsgi_app, profile_dir=".")  # type: ignore

    # Run the app
    instantiate_cache(app)
    app.run(host="0.0.0.0", port=args.port, debug=True)


if __name__ == "__main__":
    main()
