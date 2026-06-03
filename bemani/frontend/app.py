import mimetypes
import os
import re
import traceback
from typing import Callable, Dict, Any, Optional, List
from react.jsx import JSXTransformer  # type: ignore
from flask import (
    Flask,
    flash,
    request,
    redirect,
    Response,
    url_for,
    abort,
    render_template,
    got_request_exception,
    jsonify as flask_jsonify,
)
from functools import wraps

from bemani.common import AESCipher, GameConstants, cache
from bemani.data import Config, Data
from bemani.frontend.types import g
from bemani.frontend.templates import templates_location
from bemani.frontend.static import static_location

app = Flask(
    __name__,
    template_folder=templates_location,
    static_folder=static_location,
)
config = Config()


# Allow cache-busting of entire frontend for major changes such as react upgrades.
FRONTEND_CACHE_BUST: str = "site.1.3.react.16.15"


@app.before_request
def before_request() -> None:
    g.cache = cache
    g.config = config

    if request.endpoint in ["jsx", "static"]:
        # This is just serving cached compiled frontends, skip loading from DB
        return

    g.data = Data(config)
    g.sessionID = None
    g.userID = None
    try:
        aes = AESCipher(config.secret_key)
        sessionID = aes.decrypt(request.cookies.get("SessionID"))
    except Exception:
        sessionID = None
    g.sessionID = sessionID
    if sessionID is not None:
        g.userID = g.data.local.user.from_session(sessionID)
    else:
        g.userID = None


@app.after_request
def after_request(response: Response) -> Response:
    if not response.cache_control.max_age:
        # Make sure our REST calls don't get cached, so that the
        # live pages update in real-time.
        response.cache_control.no_cache = True
        response.cache_control.must_revalidate = True
        response.cache_control.private = True
    response.headers["X-Robots-Tag"] = "noindex"
    return response


@app.teardown_request
def teardown_request(exception: Any) -> None:
    data = getattr(g, "data", None)
    if data is not None:
        data.close()


def loginrequired(func: Callable) -> Callable:
    @wraps(func)
    def decoratedfunction(*args: Any, **kwargs: Any) -> Response:
        if g.userID is None:
            return redirect(url_for("account_pages.viewlogin"))  # type: ignore
        else:
            return func(*args, **kwargs)

    return decoratedfunction


def adminrequired(func: Callable) -> Callable:
    @wraps(func)
    def decoratedfunction(*args: Any, **kwargs: Any) -> Response:
        if g.userID is None:
            return redirect(url_for("account_pages.viewlogin"))  # type: ignore
        else:
            user = g.data.local.user.get_user(g.userID)
            if not user.admin:
                return Response(render_template("403.html", **{"title": "403 Forbidden"}), 403)
            else:
                return func(*args, **kwargs)

    return decoratedfunction


def loginprohibited(func: Callable) -> Callable:
    @wraps(func)
    def decoratedfunction(*args: Any, **kwargs: Any) -> Response:
        if g.userID is not None:
            return redirect(url_for("home_pages.viewhome"))  # type: ignore
        else:
            return func(*args, **kwargs)

    return decoratedfunction


def jsonify(func: Callable) -> Callable:
    @wraps(func)
    def decoratedfunction(*args: Any, **kwargs: Any) -> Response:
        try:
            return flask_jsonify(func(*args, **kwargs))
        except Exception as e:
            print(traceback.format_exc())
            return flask_jsonify(
                {
                    "error": True,
                    "message": str(e),
                }
            )

    return decoratedfunction


def cacheable(max_age: int) -> Callable:
    def __cache(func: Callable) -> Callable:
        @wraps(func)
        def decoratedfunction(*args: Any, **kwargs: Any) -> Response:
            response = func(*args, **kwargs)
            response.cache_control.max_age = max_age
            return response

        return decoratedfunction

    return __cache


# Note that this should really only be used for debug builds. In production, you should use
# the "jsx" utility to bulk convert your JSX files and put them in a directory where your
# actual webserver (nginx, apache, etc) can find them and serve them without going through
# this endpoint.
@app.route("/jsx/<path:filename>")
@cacheable(86400)
def jsx(filename: str) -> Response:
    try:
        # Figure out what our update time is to namespace on
        jsxfile = os.path.join(static_location, filename)
        normalized_path = os.path.normpath(jsxfile)
        # Check for path traversal exploit
        if not normalized_path.startswith(static_location):
            raise IOError("Path traversal exploit detected!")
        mtime = os.path.getmtime(jsxfile)
        namespace = f"{mtime}.{jsxfile}"
        jsx = g.cache.get(namespace)
        if jsx is None:
            with open(jsxfile, "rb") as f:
                transformer = JSXTransformer()
                jsx = transformer.transform_string(polyfill_fragments(f.read().decode("utf-8")))
            # Set the cache to one year, since we namespace on this file's update time
            g.cache.set(namespace, jsx, timeout=86400 * 365)
        return Response(jsx, mimetype="application/javascript")
    except Exception as exception:
        if app.debug:
            # We should make sure this error shows up on the frontend
            # much like python or template errors do.
            stack = "".join(traceback.format_exception(type(exception), exception, exception.__traceback__))
            stack = stack.replace('"', '\\"')
            stack = stack.replace("\r\n", "\\n")
            stack = stack.replace("\r", "\\n")
            stack = stack.replace("\n", "\\n")
            return Response(
                '$("ul.messages").append("<li class=\\"error\\">JSX transform error in <code>'
                + filename
                + "</code><br /><br /><pre>"
                + stack
                + '</li>");',
                mimetype="application/javascript",
            )
        else:
            # Just pass it forward like normal for production.
            raise


# Note that this should really only be used for debug builds. In production, you should use
# the "assetparse" utility to bulk convert your game asset files and put them in directories
# where your actual webserver (nginx, apache, etc) can find them and serve them without
# going through this endpoint.
@app.route("/assets/<path:filename>")
@cacheable(86400)
def assets(filename: str) -> Response:
    # Map of all assets. We could walk the config using reflection, but meh.
    assetdirs: Dict[str, str] = {
        "jubeat/emblems/": config.assets.jubeat.emblems,
    }

    # Figure out what asset pack this is from.
    for prefix, directory in assetdirs.items():
        if filename.startswith(prefix):
            filename = filename[len(prefix) :]
            normalized_path = os.path.join(directory, filename)

            # Check for path traversal exploit
            if not normalized_path.startswith(directory):
                raise IOError("Path traversal exploit detected!")

            mimetype, _ = mimetypes.guess_type(normalized_path)
            with open(normalized_path, "rb") as f:
                return Response(f.read(), mimetype=mimetype)
    else:
        # No asset for this.
        abort(404)


def polyfill_fragments(jsx: str) -> str:
    jsx = jsx.replace("<>", "<React.Fragment>")
    jsx = jsx.replace("</>", "</React.Fragment>")
    return jsx


def render_react(
    title: str,
    controller: str,
    inits: Optional[Dict[str, Any]] = None,
    links: Optional[Dict[str, Any]] = None,
) -> Response:
    if links is None:
        links = {}
    if inits is None:
        inits = {}
    links["static"] = url_for("static", filename="-1")

    return Response(
        render_template(
            "react.html",
            **{
                "title": title,
                "reactbase": f"controllers/{controller}",
                "inits": inits,
                "links": links,
            },
        )
    )


def exception(sender: Any, exception: Exception, **extra: Any) -> None:
    stack = "".join(traceback.format_exception(type(exception), exception, exception.__traceback__))
    try:
        g.data.local.network.put_event(
            "exception",
            {
                "service": "frontend",
                "request": request.url,
                "traceback": stack,
            },
        )
    except Exception:
        pass


got_request_exception.connect(exception, app)


@app.errorhandler(403)
def forbidden(error: Any) -> Response:
    return Response(render_template("403.html", **{"title": "403 Forbidden"}), 403)


@app.errorhandler(404)
def page_not_found(error: Any) -> Response:
    return Response(render_template("404.html", **{"title": "404 Not Found"}), 404)


@app.errorhandler(500)
def server_error(error: Any) -> Response:
    return Response(render_template("500.html", **{"title": "500 Internal Server Error"}), 500)


def error(msg: str) -> None:
    flash(msg, "error")


def warning(msg: str) -> None:
    flash(msg, "warning")


def success(msg: str) -> None:
    flash(msg, "success")


def info(msg: str) -> None:
    flash(msg, "info")


def valid_email(email: str) -> bool:
    return re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", email) is not None


def valid_username(username: str) -> bool:
    return re.match(r"^[a-zA-Z0-9_]+$", username) is not None


def valid_pin(pin: str, type: str) -> bool:
    if type == "card":
        return re.match(r"^\d\d\d\d$", pin) is not None
    elif type == "arcade":
        return re.match(r"^\d\d\d\d\d\d\d\d$", pin) is not None
    else:
        return False


# Define useful functions for jnija2
def jinja2_any(lval: Optional[List[Any]], pull: str, equals: str) -> bool:
    if lval is None:
        return False
    for entry in lval:
        if entry[pull] == equals:
            return True
    return False


def jinja2_theme(filename: str) -> str:
    return url_for("static", filename=f"themes/{config.theme}/{filename}")


@app.context_processor
def navigation() -> Dict[str, Any]:
    # Look up JSX components we should provide for every page load
    # Intentionally always use / to join for the top level since this
    # is returning a URI.
    components = [
        f"components/{f}"
        for f in os.listdir(os.path.join(static_location, "components"))
        if re.search(r"\.react\.js$", f)
    ]

    # Look up the logged in user ID.
    try:
        if g.userID is not None:
            user = g.data.local.user.get_user(g.userID)
            profiles = g.data.local.user.get_games_played(g.userID)
        else:
            return {
                "components": components,
                "any": jinja2_any,
                "assets": f"themes/{config.theme}/",
                "theme_url": jinja2_theme,
                "cache_bust": f"v={FRONTEND_CACHE_BUST}",
            }
    except AttributeError:
        # If we are trying to render a 500 error and we couldn't even run the
        # before request, we won't have a userID object on g. So, just give
        # up and refuse to render any navigation.
        return {
            "components": components,
            "any": jinja2_any,
            "assets": f"themes/{config.theme}/",
            "theme_url": jinja2_theme,
            "cache_bust": f"v={FRONTEND_CACHE_BUST}",
        }

    pages: List[Dict[str, Any]] = []

    # Landing page
    pages.append(
        {
            "label": "Home",
            "uri": url_for("home_pages.viewhome"),
        },
    )

    if GameConstants.BISHI_BASHI in g.config.support:
        # BishiBashi pages
        bishi_entries = []
        if len([p for p in profiles if p[0] == GameConstants.BISHI_BASHI]) > 0:
            bishi_entries.extend(
                [
                    {
                        "label": "Game Options",
                        "uri": url_for("bishi_pages.viewsettings"),
                    },
                    {
                        "label": "Personal Profile",
                        "uri": url_for("bishi_pages.viewplayer", userid=g.userID),
                    },
                ]
            )
        bishi_entries.extend(
            [
                {
                    "label": "All Players",
                    "uri": url_for("bishi_pages.viewplayers"),
                },
            ]
        )
        pages.append(
            {
                "label": "BishiBashi",
                "entries": bishi_entries,
                "base_uri": app.blueprints["bishi_pages"].url_prefix,
                "gamecode": GameConstants.BISHI_BASHI.value,
            },
        )

    if GameConstants.DANCE_EVOLUTION in g.config.support:
        # Dance Evolution pages
        danevo_entries = []
        if len([p for p in profiles if p[0] == GameConstants.DANCE_EVOLUTION]) > 0:
            danevo_entries.extend(
                [
                    {
                        "label": "Game Options",
                        "uri": url_for("danevo_pages.viewsettings"),
                    },
                    {
                        "label": "Personal Profile",
                        "uri": url_for("danevo_pages.viewplayer", userid=g.userID),
                    },
                    {
                        "label": "Dance Mates",
                        "uri": url_for("danevo_pages.viewdancemates", userid=g.userID),
                    },
                    {
                        "label": "Personal Scores",
                        "uri": url_for("danevo_pages.viewscores", userid=g.userID),
                    },
                    {
                        "label": "Personal Records",
                        "uri": url_for("danevo_pages.viewrecords", userid=g.userID),
                    },
                ]
            )
        danevo_entries.extend(
            [
                {
                    "label": "Global Scores",
                    "uri": url_for("danevo_pages.viewnetworkscores"),
                },
                {
                    "label": "Global Records",
                    "uri": url_for("danevo_pages.viewnetworkrecords"),
                },
                {
                    "label": "All Players",
                    "uri": url_for("danevo_pages.viewplayers"),
                },
            ]
        )
        pages.append(
            {
                "label": "Dance Evolution",
                "entries": danevo_entries,
                "base_uri": app.blueprints["danevo_pages"].url_prefix,
                "gamecode": GameConstants.DANCE_EVOLUTION.value,
            },
        )

    if GameConstants.DDR in g.config.support:
        # DDR pages
        ddr_entries = []
        if len([p for p in profiles if p[0] == GameConstants.DDR]) > 0:
            ddr_entries.extend(
                [
                    {
                        "label": "Game Options",
                        "uri": url_for("ddr_pages.viewsettings"),
                    },
                    {
                        "label": "Rivals",
                        "uri": url_for("ddr_pages.viewrivals"),
                    },
                    {
                        "label": "Personal Profile",
                        "uri": url_for("ddr_pages.viewplayer", userid=g.userID),
                    },
                    {
                        "label": "Personal Scores",
                        "uri": url_for("ddr_pages.viewscores", userid=g.userID),
                    },
                    {
                        "label": "Personal Records",
                        "uri": url_for("ddr_pages.viewrecords", userid=g.userID),
                    },
                ]
            )
        ddr_entries.extend(
            [
                {
                    "label": "Global Scores",
                    "uri": url_for("ddr_pages.viewnetworkscores"),
                },
                {
                    "label": "Global Records",
                    "uri": url_for("ddr_pages.viewnetworkrecords"),
                },
                {
                    "label": "All Players",
                    "uri": url_for("ddr_pages.viewplayers"),
                },
            ]
        )
        pages.append(
            {
                "label": "DDR",
                "entries": ddr_entries,
                "base_uri": app.blueprints["ddr_pages"].url_prefix,
                "gamecode": GameConstants.DDR.value,
            },
        )

    if GameConstants.IIDX in g.config.support:
        # IIDX pages
        iidx_entries = []
        if len([p for p in profiles if p[0] == GameConstants.IIDX]) > 0:
            iidx_entries.extend(
                [
                    {
                        "label": "Game Options",
                        "uri": url_for("iidx_pages.viewsettings"),
                    },
                    {
                        "label": "Rivals",
                        "uri": url_for("iidx_pages.viewrivals"),
                    },
                    {
                        "label": "Personal Profile",
                        "uri": url_for("iidx_pages.viewplayer", userid=g.userID),
                    },
                    {
                        "label": "Personal Scores",
                        "uri": url_for("iidx_pages.viewscores", userid=g.userID),
                    },
                    {
                        "label": "Personal Records",
                        "uri": url_for("iidx_pages.viewrecords", userid=g.userID),
                    },
                ]
            )
        iidx_entries.extend(
            [
                {
                    "label": "Global Scores",
                    "uri": url_for("iidx_pages.viewnetworkscores"),
                },
                {
                    "label": "Global Records",
                    "uri": url_for("iidx_pages.viewnetworkrecords"),
                },
                {
                    "label": "All Players",
                    "uri": url_for("iidx_pages.viewplayers"),
                },
            ]
        )
        pages.append(
            {
                "label": "IIDX",
                "entries": iidx_entries,
                "base_uri": app.blueprints["iidx_pages"].url_prefix,
                "gamecode": GameConstants.IIDX.value,
            },
        )

    if GameConstants.JUBEAT in g.config.support:
        # Jubeat pages
        jubeat_entries = []
        if len([p for p in profiles if p[0] == GameConstants.JUBEAT]) > 0:
            jubeat_entries.extend(
                [
                    {
                        "label": "Game Options",
                        "uri": url_for("jubeat_pages.viewsettings"),
                    },
                    {
                        "label": "Rivals",
                        "uri": url_for("jubeat_pages.viewrivals"),
                    },
                    {
                        "label": "Personal Profile",
                        "uri": url_for("jubeat_pages.viewplayer", userid=g.userID),
                    },
                    {
                        "label": "Personal Scores",
                        "uri": url_for("jubeat_pages.viewscores", userid=g.userID),
                    },
                    {
                        "label": "Personal Records",
                        "uri": url_for("jubeat_pages.viewrecords", userid=g.userID),
                    },
                ]
            )
        jubeat_entries.extend(
            [
                {
                    "label": "Global Scores",
                    "uri": url_for("jubeat_pages.viewnetworkscores"),
                },
                {
                    "label": "Global Records",
                    "uri": url_for("jubeat_pages.viewnetworkrecords"),
                },
                {
                    "label": "All Players",
                    "uri": url_for("jubeat_pages.viewplayers"),
                },
            ]
        )
        pages.append(
            {
                "label": "Jubeat",
                "entries": jubeat_entries,
                "base_uri": app.blueprints["jubeat_pages"].url_prefix,
                "gamecode": GameConstants.JUBEAT.value,
            },
        )

    if GameConstants.MGA in g.config.support:
        # Metal Gear Arcade pages
        mga_entries = []
        if len([p for p in profiles if p[0] == GameConstants.MGA]) > 0:
            mga_entries.extend(
                [
                    {
                        "label": "Game Options",
                        "uri": url_for("mga_pages.viewsettings"),
                    },
                    {
                        "label": "Personal Profile",
                        "uri": url_for("mga_pages.viewplayer", userid=g.userID),
                    },
                ]
            )
        mga_entries.extend(
            [
                {
                    "label": "All Players",
                    "uri": url_for("mga_pages.viewplayers"),
                },
            ]
        )
        pages.append(
            {
                "label": "Metal Gear Arcade",
                "entries": mga_entries,
                "base_uri": app.blueprints["mga_pages"].url_prefix,
                "gamecode": GameConstants.MGA.value,
            },
        )

    if GameConstants.MUSECA in g.config.support:
        # Museca pages
        museca_entries = []
        if len([p for p in profiles if p[0] == GameConstants.MUSECA]) > 0:
            museca_entries.extend(
                [
                    {
                        "label": "Game Options",
                        "uri": url_for("museca_pages.viewsettings"),
                    },
                    {
                        "label": "Personal Profile",
                        "uri": url_for("museca_pages.viewplayer", userid=g.userID),
                    },
                    {
                        "label": "Personal Scores",
                        "uri": url_for("museca_pages.viewscores", userid=g.userID),
                    },
                    {
                        "label": "Personal Records",
                        "uri": url_for("museca_pages.viewrecords", userid=g.userID),
                    },
                ]
            )
        museca_entries.extend(
            [
                {
                    "label": "Global Scores",
                    "uri": url_for("museca_pages.viewnetworkscores"),
                },
                {
                    "label": "Global Records",
                    "uri": url_for("museca_pages.viewnetworkrecords"),
                },
                {
                    "label": "All Players",
                    "uri": url_for("museca_pages.viewplayers"),
                },
            ]
        )
        pages.append(
            {
                "label": "MÚSECA",
                "entries": museca_entries,
                "base_uri": app.blueprints["museca_pages"].url_prefix,
                "gamecode": GameConstants.MUSECA.value,
            },
        )

    if GameConstants.POPN_MUSIC in g.config.support:
        # Pop'n Music pages
        popn_entries = []
        if len([p for p in profiles if p[0] == GameConstants.POPN_MUSIC]) > 0:
            popn_entries.extend(
                [
                    {
                        "label": "Game Options",
                        "uri": url_for("popn_pages.viewsettings"),
                    },
                    {
                        "label": "Rivals",
                        "uri": url_for("popn_pages.viewrivals"),
                    },
                    {
                        "label": "Personal Profile",
                        "uri": url_for("popn_pages.viewplayer", userid=g.userID),
                    },
                    {
                        "label": "Personal Scores",
                        "uri": url_for("popn_pages.viewscores", userid=g.userID),
                    },
                    {
                        "label": "Personal Records",
                        "uri": url_for("popn_pages.viewrecords", userid=g.userID),
                    },
                ]
            )
        popn_entries.extend(
            [
                {
                    "label": "Global Scores",
                    "uri": url_for("popn_pages.viewnetworkscores"),
                },
                {
                    "label": "Global Records",
                    "uri": url_for("popn_pages.viewnetworkrecords"),
                },
                {
                    "label": "All Players",
                    "uri": url_for("popn_pages.viewplayers"),
                },
            ]
        )
        pages.append(
            {
                "label": "Pop'n Music",
                "entries": popn_entries,
                "base_uri": app.blueprints["popn_pages"].url_prefix,
                "gamecode": GameConstants.POPN_MUSIC.value,
            },
        )

    if GameConstants.REFLEC_BEAT in g.config.support:
        # ReflecBeat pages
        reflec_entries = []
        if len([p for p in profiles if p[0] == GameConstants.REFLEC_BEAT]) > 0:
            reflec_entries.extend(
                [
                    {
                        "label": "Game Options",
                        "uri": url_for("reflec_pages.viewsettings"),
                    },
                    {
                        "label": "Rivals",
                        "uri": url_for("reflec_pages.viewrivals"),
                    },
                    {
                        "label": "Personal Profile",
                        "uri": url_for("reflec_pages.viewplayer", userid=g.userID),
                    },
                    {
                        "label": "Personal Scores",
                        "uri": url_for("reflec_pages.viewscores", userid=g.userID),
                    },
                    {
                        "label": "Personal Records",
                        "uri": url_for("reflec_pages.viewrecords", userid=g.userID),
                    },
                ]
            )
        reflec_entries.extend(
            [
                {
                    "label": "Global Scores",
                    "uri": url_for("reflec_pages.viewnetworkscores"),
                },
                {
                    "label": "Global Records",
                    "uri": url_for("reflec_pages.viewnetworkrecords"),
                },
                {
                    "label": "All Players",
                    "uri": url_for("reflec_pages.viewplayers"),
                },
            ]
        )
        pages.append(
            {
                "label": "Reflec Beat",
                "entries": reflec_entries,
                "base_uri": app.blueprints["reflec_pages"].url_prefix,
                "gamecode": GameConstants.REFLEC_BEAT.value,
            },
        )

    if GameConstants.SDVX in g.config.support:
        # SDVX pages
        sdvx_entries = []
        if len([p for p in profiles if p[0] == GameConstants.SDVX]) > 0:
            sdvx_entries.extend(
                [
                    {
                        "label": "Game Options",
                        "uri": url_for("sdvx_pages.viewsettings"),
                    },
                    {
                        "label": "Rivals",
                        "uri": url_for("sdvx_pages.viewrivals"),
                    },
                    {
                        "label": "Personal Profile",
                        "uri": url_for("sdvx_pages.viewplayer", userid=g.userID),
                    },
                    {
                        "label": "Personal Scores",
                        "uri": url_for("sdvx_pages.viewscores", userid=g.userID),
                    },
                    {
                        "label": "Personal Records",
                        "uri": url_for("sdvx_pages.viewrecords", userid=g.userID),
                    },
                ]
            )
        sdvx_entries.extend(
            [
                {
                    "label": "Global Scores",
                    "uri": url_for("sdvx_pages.viewnetworkscores"),
                },
                {
                    "label": "Global Records",
                    "uri": url_for("sdvx_pages.viewnetworkrecords"),
                },
                {
                    "label": "All Players",
                    "uri": url_for("sdvx_pages.viewplayers"),
                },
            ]
        )
        pages.append(
            {
                "label": "SDVX",
                "entries": sdvx_entries,
                "base_uri": app.blueprints["sdvx_pages"].url_prefix,
                "gamecode": GameConstants.SDVX.value,
            },
        )

    # Admin pages
    if user.admin:
        pages.append(
            {
                "label": "Admin",
                "uri": url_for("admin_pages.viewsettings"),
                "entries": [
                    {
                        "label": "Events",
                        "uri": url_for("admin_pages.viewevents"),
                    },
                    {
                        "label": "Data API",
                        "uri": url_for("admin_pages.viewapi"),
                    },
                    {
                        "label": "Arcades",
                        "uri": url_for("admin_pages.viewarcades"),
                    },
                    {
                        "label": "PCBIDs",
                        "uri": url_for("admin_pages.viewmachines"),
                    },
                    {
                        "label": "Game Settings",
                        "uri": url_for("admin_pages.viewgamesettings"),
                    },
                    {
                        "label": "Cards",
                        "uri": url_for("admin_pages.viewcards"),
                    },
                    {
                        "label": "Users",
                        "uri": url_for("admin_pages.viewusers"),
                    },
                    {
                        "label": "News",
                        "uri": url_for("admin_pages.viewnews"),
                    },
                ],
                "base_uri": app.blueprints["admin_pages"].url_prefix,
                "right_justify": True,
            },
        )

    # Arcade owner pages
    arcadeids = g.data.local.machine.from_userid(g.userID)
    if len(arcadeids) == 1:
        arcade = g.data.local.machine.get_arcade(arcadeids[0])
        pages.append(
            {
                "label": arcade.name,
                "uri": url_for("arcade_pages.viewarcade", arcadeid=arcade.id),
                "right_justify": True,
            }
        )
    elif len(arcadeids) > 1:
        entries = []
        for arcadeid in arcadeids:
            arcade = g.data.local.machine.get_arcade(arcadeid)
            entries.append(
                {
                    "label": arcade.name,
                    "uri": url_for("arcade_pages.viewarcade", arcadeid=arcade.id),
                }
            )

        pages.append(
            {
                "label": "Arcades",
                "entries": entries,
                "base_uri": app.blueprints["arcade_pages"].url_prefix,
                "right_justify": True,
            }
        )

    # User account pages
    pages.append(
        {
            "label": "Account",
            "uri": url_for("account_pages.viewaccount"),
            "entries": [
                {
                    "label": "Cards",
                    "uri": url_for("account_pages.viewcards"),
                },
            ],
            "base_uri": app.blueprints["account_pages"].url_prefix,
            "right_justify": True,
        },
    )

    # GTFO button
    pages.append(
        {
            "label": "Log Out",
            "uri": url_for("account_pages.logout"),
            "right_justify": True,
        },
    )

    return {
        "current_path": request.path,
        "show_navigation": True,
        "navigation": pages,
        "components": components,
        "any": jinja2_any,
        "assets": f"themes/{config.theme}/",
        "theme_url": jinja2_theme,
        "cache_bust": f"v={FRONTEND_CACHE_BUST}",
    }
