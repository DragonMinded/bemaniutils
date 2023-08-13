from flask import Flask
from flask_caching import Cache


# This somewhat breaks convention of trying to keep flask stuff in only the application
# routing layer, but flask-caching itself is a useful wrapper that supports a ton of
# backends like in-memory, filesystem, redis, memcached, etc. So, we centralize the
# object's ownership here and call into this to initialize it during application setup
# so that anywhere in the codebase can assume an initialized cache object for decorators.
app = Flask(__name__)

cache = Cache(
    app,
    # We should overwrite this in any reasonable entrypoint to the system, but for simple
    # utilities that don't want to set up the entire infrastructure, provide a sane default.
    config={"CACHE_TYPE": "SimpleCache"},
)
