import time
import boto3
from datetime import datetime, timezone
from boto3.dynamodb.conditions import Key, Attr
from flask_login import current_user, login_user, logout_user, login_required
from flask import redirect, url_for, render_template, request, flash, current_app
from werkzeug.urls import url_parse
from app.auth import bp
from app.auth.forms import LoginForm, ChangePasswordForm
from werkzeug.utils import secure_filename
import os
from shutil import copyfile
CURRENT_USER = None


@current_app.login_manager.user_loader
def load_user(id):
    if CURRENT_USER and CURRENT_USER.id == id:
        return CURRENT_USER
    return None


class Cog_User:
    def __init__(self, is_active, is_authenticated, username, access_token, id_token, token_type):
        if 'admin' in username:
            self.id = 1
        else:
            self.id = 2
        self.is_active = is_active
        self.is_authenticated = is_authenticated
        self.username = username
        self.access_token = access_token
        self.id_token = id_token
        self.token_type = token_type

    def __getattr__(self, name):
        return getattr(self.instance, name)

    def get_id(self):
        return self.id


@bp.route('/login', methods=['GET', 'POST'])
def login():
    global CURRENT_USER
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    l_form = LoginForm()
    c_form = ChangePasswordForm()
    client = boto3.client('cognito-idp', region_name=current_app.config['AWS_DEFAULT_REGION'],
                          aws_access_key_id=current_app.config['AWS_ACCESS_KEY_ID'],
                            aws_secret_access_key=current_app.config['AWS_SECRET_ACCESS_KEY'])
    # Login page logic
    if l_form.validate_on_submit():
        result = request.form.to_dict()
        try:
            tokens = client.initiate_auth(AuthFlow='USER_PASSWORD_AUTH',
                                          ClientId=current_app.config['AWS_COGNITO_USER_POOL_CLIENT_ID'],
                                          AuthParameters={'USERNAME': result['username'],
                                                          'PASSWORD': result['password']})
            if 'ChallengeName' in tokens:
                if tokens['ChallengeName'] == 'NEW_PASSWORD_REQUIRED':
                    c_form = ChangePasswordForm()
                    c_form.username.data = result['username']
                    return render_template('login.html', title='Sign In', type='Change', form=c_form)

            CURRENT_USER = Cog_User(is_active=True, is_authenticated=True, username=result['username'],
                                    access_token=tokens['AuthenticationResult']['AccessToken'],
                                    id_token=tokens['AuthenticationResult']['IdToken'],
                                    token_type=tokens['AuthenticationResult']['TokenType'])
            login_user(CURRENT_USER)
            next_page = request.args.get('next')
            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('auth.admin')
            return redirect(next_page)

        except client.exceptions.UserNotFoundException:
            flash('Invalid username or password', 'error')
            return redirect(url_for('auth.login'))
        except client.exceptions.PasswordResetRequiredException as PSRE:
            c_form.username.data = result['username']
            return render_template('login.html', title='Sign In', type='Change', form=c_form)
        except client.exceptions.NotAuthorizedException as NAE:
            flash('Invalid username or password', 'error')
            return redirect(url_for('auth.login'))
        except Exception as e:
            flash('Please try again.', 'error')
            return redirect(url_for('auth.login'))

    # Change password logic
    elif c_form.validate_on_submit():
        result = request.form.to_dict()
        if result['new_password'] != result['confirm_password']:
            flash('Invalid username or password', 'error')
            return render_template('login.html', title='Sign In', type='Change', form=c_form)
        try:
            access_token = None
            tokens = client.initiate_auth(AuthFlow='USER_PASSWORD_AUTH',
                                          ClientId=current_app.config['AWS_COGNITO_USER_POOL_CLIENT_ID'],
                                          AuthParameters={'USERNAME': result['username'],
                                                          'PASSWORD': result['prev_password']})
            if 'ChallengeName' in tokens:
                if tokens['ChallengeName'] == 'NEW_PASSWORD_REQUIRED':
                    response = client.respond_to_auth_challenge(
                        ClientId=current_app.config['AWS_COGNITO_USER_POOL_CLIENT_ID'],
                        ChallengeName=tokens['ChallengeName'],
                        Session=tokens['Session'],
                        ChallengeResponses={'NEW_PASSWORD': result['new_password'],
                                            'USERNAME': result['username']})
                    access_token = response['AuthenticationResult']['AccessToken']

            if access_token:
                CURRENT_USER = Cog_User(is_active=True, is_authenticated=True, username=result['username'],
                                        access_token=response['AuthenticationResult']['AccessToken'],
                                        id_token=response['AuthenticationResult']['IdToken'],
                                        token_type=response['AuthenticationResult']['TokenType'])
                login_user(CURRENT_USER)
                next_page = request.args.get('next')
                if not next_page or url_parse(next_page).netloc != '':
                    next_page = url_for('auth.admin')
                return redirect(next_page)
            else:
                flash('Contact Admin to change Password!', 'error')
                return render_template('login.html', title='Sign In', type='Change', form=c_form)
        except client.exceptions.InvalidPasswordException:
            flash('Invalid Password!', 'error')
            return render_template('login.html', title='Sign In', type='Change', form=c_form)
        except Exception as e:
            flash('Unable to update Password!', 'error')
            return render_template('login.html', title='Sign In', type='Change', form=c_form)

    return render_template('login.html', title='Sign In', type='Login', form=l_form)


TOTAL_ITEMS = 0


@bp.route('/admin')
@login_required
def admin():
    return render_template('admin.html')


def allowed_image(filename):
    if not "." in filename:
        return False
    ext = filename.rsplit(".", 1)[1]
    if ext.upper() in current_app.config["ALLOWED_IMAGE_EXTENSIONS"]:
        return True
    else:
        return False


def allowed_image_filesize(filesize):
    if int(filesize) <= current_app.config["MAX_IMAGE_FILESIZE"]:
        return True
    else:
        return False


@bp.route("/upload-image", methods=["GET", "POST"])
@login_required
def upload_image():
    if request.method == "POST":
        if request.files:
            if request.content_length:
                if not allowed_image_filesize(request.content_length):
                    current_app.logger.error(f"Filesize exceed maximum limit {request.content_length}")
                    flash('Filesize exceeded maximum limit', 'error')
                    return redirect(request.url)
                image = request.files["image"]
                if image.filename == "":
                    flash('No filename', 'error')
                    return redirect(request.url)
                if allowed_image(image.filename):
                    filename = secure_filename(image.filename)
                    image.save(os.path.join(current_app.config["IMAGE_UPLOADS"], filename))
                    copyfile(os.path.join(current_app.config["IMAGE_UPLOADS"], filename),
                        os.path.join(current_app.config["IMAGE_UPLOADS"], 'SPOTIFY_COVER.png'))
                    current_app.logger.info(f"Image Saved, {filename}")
                    flash('Image saved!', 'success')
                    return redirect(request.url)
                else:
                    current_app.logger.error(f'File extension not allowed, {image.filename}')
                    flash('That file extension is not allowed!', 'error')
                    return redirect(request.url)
    return render_template("upload_image.html")


@bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.index'))
