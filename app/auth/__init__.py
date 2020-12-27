from flask import Blueprint

bp = Blueprint('auth', __name__, template_folder='./templates', static_folder='./auth_static')

from app.auth import routes
