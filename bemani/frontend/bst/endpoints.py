import re
from typing import Any, Dict, List, Optional
from flask import Blueprint, request, Response, url_for, abort

from bemani.common import ID, GameConstants
from bemani.data import Link, UserID
from bemani.frontend.app import loginrequired, jsonify, render_react
from bemani.frontend.bst.bst import BSTFrontend
from bemani.frontend.templates import templates_location
from bemani.frontend.static import static_location
from bemani.frontend.types import g

bst_pages = Blueprint(
    'bst_pages',
    __name__,
    url_prefix=f'/{GameConstants.BST.value}',
    template_folder=templates_location,
    static_folder=static_location,
)

@bst_pages.route("/scores")
@loginrequired
def viewnetworkscores() -> Response:
    frontend = BSTFrontend(g.data, g.config, g.cache)
    network_scores = frontend.get_network_scores(limit=100)
    if len(network_scores['attempts']) > 10:
        network_scores['attempts'] = frontend.round_to_ten(network_scores['attempts'])

    return render_react(
        'Global DDR Scores',
        'bst/scores.react.js',
        {
            'attempts': network_scores['attempts'],
            'songs': frontend.get_all_songs(),
            'players': network_scores['players'],
            'versions': {version: name for (game, version, name) in frontend.all_games()},
            'shownames': True,
            'shownewrecords': False,
        },
        {
            'refresh': url_for('bst_pages.listnetworkscores'),
            'player': url_for('bst_pages.viewplayer', userid=-1),
            'individual_score': url_for('bst_pages.viewtopscores', musicid=-1),
        },
    )

@bst_pages.route('/scores/list')
@jsonify
@loginrequired
def listnetworkscores() -> Dict[str, Any]:
    frontend = BSTFrontend(g.data, g.config, g.cache)
    return frontend.get_network_scores()