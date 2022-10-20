import argparse

from bemani.api import app, config  # noqa: F401
from bemani.utils.config import load_config as base_load_config


def load_config(filename: str) -> None:
    global config
    base_load_config(filename, config)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="An API services provider for eAmusement games, conforming to BEMAPI specs."
    )
    parser.add_argument(
        "-p", "--port", help="Port to listen on. Defaults to 80", type=int, default=80
    )
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
        help="Turn on profiling for API, writing CProfile data to the currenct directory",
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

    if args.profile:
        from werkzeug.contrib.profiler import ProfilerMiddleware

        app.wsgi_app = ProfilerMiddleware(app.wsgi_app, profile_dir=".")  # type: ignore

    # Run the app
    app.run(host="0.0.0.0", port=args.port, debug=True)


if __name__ == "__main__":
    main()
