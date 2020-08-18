import os
import re
import traceback
from typing import Callable, Dict, Any, Optional, List
from react.jsx import JSXTransformer  # type: ignore
from flask import Flask, flash, request, redirect, Response, url_for, render_template, got_request_exception, jsonify as flask_jsonify, g
from flask_caching import Cache  # type: ignore
from functools import wraps

from bemani.common import AESCipher, GameConstants
from bemani.data import Data
from bemani.frontend.templates import templates_location
from bemani.frontend.static import static_location

app = Flask(
    __name__,
    template_folder=templates_location,
    static_folder=static_location,
)
config: Dict[str, Any] = {}


@app.before_request
def before_request() -> None:
    global config
    g.cache = Cache(app, config={
        'CACHE_TYPE': 'filesystem',
        'CACHE_DIR': config['cache_dir'],
    })
    if request.endpoint in ['jsx', 'static']:
        # This is just serving cached compiled frontends, skip loading from DB
        return

    g.config = config
    g.data = Data(config)
    g.sessionID = None
    g.userID = None
    try:
        aes = AESCipher(config['secret_key'])
        sessionID = aes.decrypt(request.cookies.get('SessionID'))
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
    return response


@app.teardown_request
def teardown_request(exception: Any) -> None:
    data = getattr(g, 'data', None)
    if data is not None:
        data.close()


def loginrequired(func: Callable) -> Callable:
    @wraps(func)
    def decoratedfunction(*args: Any, **kwargs: Any) -> Response:
        if g.userID is None:
            return redirect(url_for('account_pages.viewlogin'))  # type: ignore
        else:
            return func(*args, **kwargs)
    return decoratedfunction


def adminrequired(func: Callable) -> Callable:
    @wraps(func)
    def decoratedfunction(*args: Any, **kwargs: Any) -> Response:
        if g.userID is None:
            return redirect(url_for('account_pages.viewlogin'))  # type: ignore
        else:
            user = g.data.local.user.get_user(g.userID)
            if not user.admin:
                return Response(render_template('403.html', **{'title': '403 Forbidden'}), 403)
            else:
                return func(*args, **kwargs)
    return decoratedfunction


def loginprohibited(func: Callable) -> Callable:
    @wraps(func)
    def decoratedfunction(*args: Any, **kwargs: Any) -> Response:
        if g.userID is not None:
            return redirect(url_for('home_pages.viewhome'))  # type: ignore
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
            return flask_jsonify({
                'error': True,
                'message': str(e),
            })
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


@app.route('/jsx/<path:filename>')
@cacheable(86400)
def jsx(filename: str) -> Response:
    # Figure out what our update time is to namespace on
    jsxfile = os.path.join(static_location, filename)
    mtime = os.path.getmtime(jsxfile)
    namespace = f'{mtime}.{jsxfile}'
    jsx = g.cache.get(namespace)
    if jsx is None:
        with open(jsxfile, 'rb') as f:
            transformer = JSXTransformer()
            jsx = transformer.transform_string(f.read().decode('utf-8'))
        # Set the cache to one year, since we namespace on this file's update time
        g.cache.set(namespace, jsx, timeout=86400 * 365)
    return Response(jsx, mimetype='application/javascript')


def render_react(
    title: str,
    controller: str,
    inits: Optional[Dict[str, Any]]=None,
    links: Optional[Dict[str, Any]]=None,
) -> Response:
    if links is None:
        links = {}
    if inits is None:
        inits = {}
    links['static'] = url_for('static', filename='-1')

    return Response(render_template(
        'react.html',
        **{
            'title': title,
            'reactbase': os.path.join('controllers/', controller),
            'inits': inits,
            'links': links,
        },
    ))


def exception(sender: Any, exception: Exception, **extra: Any) -> None:
    stack = ''.join(traceback.format_exception(type(exception), exception, exception.__traceback__))
    try:
        g.data.local.network.put_event(
            'exception',
            {
                'service': 'frontend',
                'request': request.url,
                'traceback': stack,
            },
        )
    except Exception:
        pass


got_request_exception.connect(exception, app)


@app.errorhandler(403)
def forbidden(error: Any) -> Response:
    return Response(render_template('403.html', **{'title': '403 Forbidden'}), 403)


@app.errorhandler(404)
def page_not_found(error: Any) -> Response:
    return Response(render_template('404.html', **{'title': '404 Not Found'}), 404)


@app.errorhandler(500)
def server_error(error: Any) -> Response:
    return Response(render_template('500.html', **{'title': '500 Internal Server Error'}), 500)


def error(msg: str) -> None:
    flash(msg, 'error')


def warning(msg: str) -> None:
    flash(msg, 'warning')


def success(msg: str) -> None:
    flash(msg, 'success')


def info(msg: str) -> None:
    flash(msg, 'info')


def valid_email(email: str) -> bool:
    return re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", email) is not None


def valid_username(username: str) -> bool:
    return re.match(r"^[a-zA-Z0-9_]+$", username) is not None


def valid_pin(pin: str, type: str) -> bool:
    if type == 'card':
        return re.match(r"\d\d\d\d", pin) is not None
    elif type == 'arcade':
        return re.match(r"\d\d\d\d\d\d\d\d", pin) is not None
    else:
        return False


@app.context_processor
def navigation() -> Dict[str, Any]:
    # Look up JSX components we should provide for every page load
    components = [
        os.path.join('components/', f)
        for f in os.listdir(os.path.join(static_location, 'components/'))
        if re.search(r'\.react\.js$', f)
    ]

    # Define useful functions for jnija2
    def jinja2_any(lval: Optional[List[Any]], pull: str, equals: str) -> bool:
        if lval is None:
            return False
        for entry in lval:
            if entry[pull] == equals:
                return True
        return False

    # Look up the logged in user ID.
    if g.userID is not None:
        user = g.data.local.user.get_user(g.userID)
        profiles = g.data.local.user.get_games_played(g.userID)
    else:
        return {
            'components': components,
            'any': jinja2_any,
        }
    pages = []

    # Landing page
    pages.append(
        {
            'label': 'Home',
            'uri': url_for('home_pages.viewhome'),
        },
    )

    if g.config.get('support', {}).get(GameConstants.BISHI_BASHI, False):
        # BishiBashi pages
        bishi_entries = []
        if len([p for p in profiles if p[0] == GameConstants.BISHI_BASHI]) > 0:
            bishi_entries.extend([
                {
                    'label': 'Game Options',
                    'uri': url_for('bishi_pages.viewsettings'),
                },
                {
                    'label': 'Personal Profile',
                    'uri': url_for('bishi_pages.viewplayer', userid=g.userID),
                },
            ])
        bishi_entries.extend([
            {
                'label': 'All Players',
                'uri': url_for('bishi_pages.viewplayers'),
            },
        ])
        pages.append(
            {
                'label': 'BishiBashi',
                'entries': bishi_entries,
                'base_uri': app.blueprints['bishi_pages'].url_prefix,
                'gamecode': GameConstants.BISHI_BASHI,
            },
        )

    if g.config.get('support', {}).get(GameConstants.DDR, False):
        # DDR pages
        ddr_entries = []
        if len([p for p in profiles if p[0] == GameConstants.DDR]) > 0:
            ddr_entries.extend([
                {
                    'label': 'Game Options',
                    'uri': url_for('ddr_pages.viewsettings'),
                },
                {
                    'label': 'Rivals',
                    'uri': url_for('ddr_pages.viewrivals'),
                },
                {
                    'label': 'Personal Profile',
                    'uri': url_for('ddr_pages.viewplayer', userid=g.userID),
                },
                {
                    'label': 'Personal Scores',
                    'uri': url_for('ddr_pages.viewscores', userid=g.userID),
                },
                {
                    'label': 'Personal Records',
                    'uri': url_for('ddr_pages.viewrecords', userid=g.userID),
                },
            ])
        ddr_entries.extend([
            {
                'label': 'Global Scores',
                'uri': url_for('ddr_pages.viewnetworkscores'),
            },
            {
                'label': 'Global Records',
                'uri': url_for('ddr_pages.viewnetworkrecords'),
            },
            {
                'label': 'All Players',
                'uri': url_for('ddr_pages.viewplayers'),
            },
        ])
        pages.append(
            {
                'label': 'DDR',
                'entries': ddr_entries,
                'base_uri': app.blueprints['ddr_pages'].url_prefix,
                'gamecode': GameConstants.DDR,
            },
        )

    if g.config.get('support', {}).get(GameConstants.IIDX, False):
        # IIDX pages
        iidx_entries = []
        if len([p for p in profiles if p[0] == GameConstants.IIDX]) > 0:
            iidx_entries.extend([
                {
                    'label': 'Game Options',
                    'uri': url_for('iidx_pages.viewsettings'),
                },
                {
                    'label': 'Rivals',
                    'uri': url_for('iidx_pages.viewrivals'),
                },
                {
                    'label': 'Personal Profile',
                    'uri': url_for('iidx_pages.viewplayer', userid=g.userID),
                },
                {
                    'label': 'Personal Scores',
                    'uri': url_for('iidx_pages.viewscores', userid=g.userID),
                },
                {
                    'label': 'Personal Records',
                    'uri': url_for('iidx_pages.viewrecords', userid=g.userID),
                },
            ])
        iidx_entries.extend([
            {
                'label': 'Global Scores',
                'uri': url_for('iidx_pages.viewnetworkscores'),
            },
            {
                'label': 'Global Records',
                'uri': url_for('iidx_pages.viewnetworkrecords'),
            },
            {
                'label': 'All Players',
                'uri': url_for('iidx_pages.viewplayers'),
            },
        ])
        pages.append(
            {
                'label': 'IIDX',
                'entries': iidx_entries,
                'base_uri': app.blueprints['iidx_pages'].url_prefix,
                'gamecode': GameConstants.IIDX,
            },
        )

    if g.config.get('support', {}).get(GameConstants.JUBEAT, False):
        # Jubeat pages
        jubeat_entries = []
        if len([p for p in profiles if p[0] == GameConstants.JUBEAT]) > 0:
            jubeat_entries.extend([
                {
                    'label': 'Game Options',
                    'uri': url_for('jubeat_pages.viewsettings'),
                },
                {
                    'label': 'Rivals',
                    'uri': url_for('jubeat_pages.viewrivals'),
                },
                {
                    'label': 'Personal Profile',
                    'uri': url_for('jubeat_pages.viewplayer', userid=g.userID),
                },
                {
                    'label': 'Personal Scores',
                    'uri': url_for('jubeat_pages.viewscores', userid=g.userID),
                },
                {
                    'label': 'Personal Records',
                    'uri': url_for('jubeat_pages.viewrecords', userid=g.userID),
                },
            ])
        jubeat_entries.extend([
            {
                'label': 'Global Scores',
                'uri': url_for('jubeat_pages.viewnetworkscores'),
            },
            {
                'label': 'Global Records',
                'uri': url_for('jubeat_pages.viewnetworkrecords'),
            },
            {
                'label': 'All Players',
                'uri': url_for('jubeat_pages.viewplayers'),
            },
        ])
        pages.append(
            {
                'label': 'Jubeat',
                'entries': jubeat_entries,
                'base_uri': app.blueprints['jubeat_pages'].url_prefix,
                'gamecode': GameConstants.JUBEAT,
            },
        )

    if g.config.get('support', {}).get(GameConstants.MUSECA, False):
        # Museca pages
        museca_entries = []
        if len([p for p in profiles if p[0] == GameConstants.MUSECA]) > 0:
            museca_entries.extend([
                {
                    'label': 'Game Options',
                    'uri': url_for('museca_pages.viewsettings'),
                },
                {
                    'label': 'Personal Profile',
                    'uri': url_for('museca_pages.viewplayer', userid=g.userID),
                },
                {
                    'label': 'Personal Scores',
                    'uri': url_for('museca_pages.viewscores', userid=g.userID),
                },
                {
                    'label': 'Personal Records',
                    'uri': url_for('museca_pages.viewrecords', userid=g.userID),
                },
            ])
        museca_entries.extend([
            {
                'label': 'Global Scores',
                'uri': url_for('museca_pages.viewnetworkscores'),
            },
            {
                'label': 'Global Records',
                'uri': url_for('museca_pages.viewnetworkrecords'),
            },
            {
                'label': 'All Players',
                'uri': url_for('museca_pages.viewplayers'),
            },
        ])
        pages.append(
            {
                'label': 'MÚSECA',
                'entries': museca_entries,
                'base_uri': app.blueprints['museca_pages'].url_prefix,
                'gamecode': GameConstants.MUSECA,
            },
        )

    if g.config.get('support', {}).get(GameConstants.POPN_MUSIC, False):
        # Pop'n Music pages
        popn_entries = []
        if len([p for p in profiles if p[0] == GameConstants.POPN_MUSIC]) > 0:
            popn_entries.extend([
                {
                    'label': 'Game Options',
                    'uri': url_for('popn_pages.viewsettings'),
                },
                {
                    'label': 'Rivals',
                    'uri': url_for('popn_pages.viewrivals'),
                },
                {
                    'label': 'Personal Profile',
                    'uri': url_for('popn_pages.viewplayer', userid=g.userID),
                },
                {
                    'label': 'Personal Scores',
                    'uri': url_for('popn_pages.viewscores', userid=g.userID),
                },
                {
                    'label': 'Personal Records',
                    'uri': url_for('popn_pages.viewrecords', userid=g.userID),
                },
            ])
        popn_entries.extend([
            {
                'label': 'Global Scores',
                'uri': url_for('popn_pages.viewnetworkscores'),
            },
            {
                'label': 'Global Records',
                'uri': url_for('popn_pages.viewnetworkrecords'),
            },
            {
                'label': 'All Players',
                'uri': url_for('popn_pages.viewplayers'),
            },
        ])
        pages.append(
            {
                'label': 'Pop\'n Music',
                'entries': popn_entries,
                'base_uri': app.blueprints['popn_pages'].url_prefix,
                'gamecode': GameConstants.POPN_MUSIC,
            },
        )

    if g.config.get('support', {}).get(GameConstants.REFLEC_BEAT, False):
        # ReflecBeat pages
        reflec_entries = []
        if len([p for p in profiles if p[0] == GameConstants.REFLEC_BEAT]) > 0:
            reflec_entries.extend([
                {
                    'label': 'Game Options',
                    'uri': url_for('reflec_pages.viewsettings'),
                },
                {
                    'label': 'Rivals',
                    'uri': url_for('reflec_pages.viewrivals'),
                },
                {
                    'label': 'Personal Profile',
                    'uri': url_for('reflec_pages.viewplayer', userid=g.userID),
                },
                {
                    'label': 'Personal Scores',
                    'uri': url_for('reflec_pages.viewscores', userid=g.userID),
                },
                {
                    'label': 'Personal Records',
                    'uri': url_for('reflec_pages.viewrecords', userid=g.userID),
                },
            ])
        reflec_entries.extend([
            {
                'label': 'Global Scores',
                'uri': url_for('reflec_pages.viewnetworkscores'),
            },
            {
                'label': 'Global Records',
                'uri': url_for('reflec_pages.viewnetworkrecords'),
            },
            {
                'label': 'All Players',
                'uri': url_for('reflec_pages.viewplayers'),
            },
        ])
        pages.append(
            {
                'label': 'Reflec Beat',
                'entries': reflec_entries,
                'base_uri': app.blueprints['reflec_pages'].url_prefix,
                'gamecode': GameConstants.REFLEC_BEAT,
            },
        )

    if g.config.get('support', {}).get(GameConstants.SDVX, False):
        # SDVX pages
        sdvx_entries = []
        if len([p for p in profiles if p[0] == GameConstants.SDVX]) > 0:
            sdvx_entries.extend([
                {
                    'label': 'Game Options',
                    'uri': url_for('sdvx_pages.viewsettings'),
                },
                {
                    'label': 'Rivals',
                    'uri': url_for('sdvx_pages.viewrivals'),
                },
                {
                    'label': 'Personal Profile',
                    'uri': url_for('sdvx_pages.viewplayer', userid=g.userID),
                },
                {
                    'label': 'Personal Scores',
                    'uri': url_for('sdvx_pages.viewscores', userid=g.userID),
                },
                {
                    'label': 'Personal Records',
                    'uri': url_for('sdvx_pages.viewrecords', userid=g.userID),
                },
            ])
        sdvx_entries.extend([
            {
                'label': 'Global Scores',
                'uri': url_for('sdvx_pages.viewnetworkscores'),
            },
            {
                'label': 'Global Records',
                'uri': url_for('sdvx_pages.viewnetworkrecords'),
            },
            {
                'label': 'All Players',
                'uri': url_for('sdvx_pages.viewplayers'),
            },
        ])
        pages.append(
            {
                'label': 'SDVX',
                'entries': sdvx_entries,
                'base_uri': app.blueprints['sdvx_pages'].url_prefix,
                'gamecode': GameConstants.SDVX,
            },
        )

    # Admin pages
    if user.admin:
        pages.append(
            {
                'label': 'Admin',
                'uri': url_for('admin_pages.viewsettings'),
                'entries': [
                    {
                        'label': 'Events',
                        'uri': url_for('admin_pages.viewevents'),
                    },
                    {
                        'label': 'Data API',
                        'uri': url_for('admin_pages.viewapi'),
                    },
                    {
                        'label': 'Arcades',
                        'uri': url_for('admin_pages.viewarcades'),
                    },
                    {
                        'label': 'Machines',
                        'uri': url_for('admin_pages.viewmachines'),
                    },
                    {
                        'label': 'Cards',
                        'uri': url_for('admin_pages.viewcards'),
                    },
                    {
                        'label': 'Users',
                        'uri': url_for('admin_pages.viewusers'),
                    },
                    {
                        'label': 'News',
                        'uri': url_for('admin_pages.viewnews'),
                    },
                ],
                'base_uri': app.blueprints['admin_pages'].url_prefix,
                'right_justify': True,
            },
        )

    # Arcade owner pages
    arcadeids = g.data.local.machine.from_userid(g.userID)
    if len(arcadeids) > 0:
        entries = []
        for arcadeid in arcadeids:
            arcade = g.data.local.machine.get_arcade(arcadeid)
            entries.append({
                'label': arcade.name,
                'uri': url_for('arcade_pages.viewarcade', arcadeid=arcade.id),
            })

        pages.append({
            'label': 'Arcades',
            'entries': entries,
            'base_uri': app.blueprints['arcade_pages'].url_prefix,
            'right_justify': True,
        })

    # User account pages
    pages.append(
        {
            'label': 'Account',
            'uri': url_for('account_pages.viewaccount'),
            'entries': [
                {
                    'label': 'Cards',
                    'uri': url_for('account_pages.viewcards'),
                },
            ],
            'base_uri': app.blueprints['account_pages'].url_prefix,
            'right_justify': True,
        },
    )

    # GTFO button
    pages.append(
        {
            'label': 'Log Out',
            'uri': url_for('account_pages.logout'),
            'right_justify': True,
        },
    )

    return {
        'current_path': request.path,
        'show_navigation': True,
        'navigation': pages,
        'components': components,
        'any': jinja2_any,
    }
