from flask import Blueprint, Response
from typing import Dict, Any

from bemani.data import News
from bemani.frontend.app import loginrequired, render_react
from bemani.frontend.templates import templates_location
from bemani.frontend.static import static_location
from bemani.frontend.types import g


home_pages = Blueprint(
    "home_pages",
    __name__,
    template_folder=templates_location,
    static_folder=static_location,
)


def format_news(news: News) -> Dict[str, Any]:
    return {
        "timestamp": news.timestamp,
        "title": news.title,
        "body": news.body,
    }


@home_pages.route("/")
@loginrequired
def viewhome() -> Response:
    return render_react(
        g.config.get("name", "e-AMUSEMENT Network"),
        "home.react.js",
        {
            "news": [format_news(news) for news in g.data.local.network.get_all_news()],
        },
    )
