import datetime
import json
import os

from boto3.dynamodb.conditions import Key
from flask import render_template, send_from_directory, request
from app.main import bp
from flask import current_app

@bp.route('/')
def index():

    return render_template('index.html', title='Home')

@bp.route('/robots.txt')
@bp.route('/sitemap.xml')
@bp.route('/favicon.ico')
def static_from_root():
    return send_from_directory(current_app.config['APP_STATIC'], request.path[1:])
