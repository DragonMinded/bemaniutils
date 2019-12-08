from bemani.utils.proxy import app, load_config

# Assumes a proxy yaml in the same directory as this WSGI
# file. Also assumes that your uWSGI instance is configured with a
# virtualenv that includes the installed version of this repo.
load_config('proxy.yaml')
