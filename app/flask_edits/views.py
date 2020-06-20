"""Edits Admin Blueprint
"""

import json
from flask import (
    Blueprint,
    current_app,
    render_template,
    request,
    redirect,
    url_for,
)
from flask_login import login_required
from jinja2.environment import copy_cache

edits = Blueprint('edits', __name__, template_folder='templates', static_folder='static')

@edits.route('/', defaults={'page': None})
@edits.route('/<path:page>')
@login_required
def index(page):
    _db = current_app.jinja_env.edits

    if _db:
        if not page:
            page = next(iter(_db.keys()))
    else:
        page = None

    return render_template('edit_content.html',
                           edits=_db,
                           page=page,
                           summernote=current_app.config['EDITS_SUMMERNOTE'],
                           preview=current_app.jinja_env.edits_preview)

@edits.route('/preview', methods=['POST'])
def preview():
    if request.form.get('state') == 'true':
        preview = True
        cache = None
    else:
        preview = False
        cache = copy_cache(current_app.jinja_env.edits_cache)

    current_app.jinja_env.edits_preview = preview
    current_app.jinja_env.cache = cache

    if current_app.jinja_env.cache:
        current_app.jinja_env.cache.clear()

    return ''

@edits.route('/save', methods=['POST'])
@login_required
def save():
    _db = current_app.jinja_env.edits

    page = request.form.get('page')

    for field in request.form:
        if field != 'page':
            value = request.form.get(field)

            if value == '':
                value = None

            _db[page][field]['edited'] = value

    if current_app.jinja_env.cache:
        current_app.jinja_env.cache.clear()

    with open(current_app.config['EDITS_PATH'], 'w') as f:
        f.write(json.dumps(_db, indent=4))

    return redirect(url_for('edits.index', page=page))
