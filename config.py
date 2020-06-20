import json
import os

import boto3
from boto3 import Session
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.flaskenv'), verbose=True)
with open(os.path.join(basedir, 'app/static/KEYS/aws.json')) as f:
    key = json.loads(f.read())

class Config(object):
    APP_root = basedir
    APP_STATIC = os.path.join(basedir, 'app/static')
    EDITS_PATH = os.path.join(basedir, 'app/static/edits/edits.json')
    MAX_IMAGE_FILESIZE = 4 * 1024 * 1024
    IMAGE_UPLOADS = os.path.join(APP_STATIC, 'img')
    ALLOWED_IMAGE_EXTENSIONS = ["JPEG", "JPG", "PNG", "GIF"]
    SECRET_KEY = os.environ.get('SECRET_KEY')


    AWS_ACCESS_KEY_ID = key['AWS_ACCESS_KEY_ID']
    AWS_SECRET_ACCESS_KEY = key['AWS_SECRET_ACCESS_KEY']
    AWS_DEFAULT_REGION = key['AWS_DEFAULT_REGION']
    boto_sess = Session(
        region_name=AWS_DEFAULT_REGION,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY
    )
    DYNAMO_SESSION = boto_sess
    DYNAMO_CLIENT = boto3.resource('dynamodb', region_name=AWS_DEFAULT_REGION,
                                   aws_access_key_id=AWS_ACCESS_KEY_ID,
                                   aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    COGNITO_REGION = key['COGNITO_REGION']
    COGNITO_USERPOOL_ID = key['COGNITO_USERPOOL_ID']
    AWS_COGNITO_DOMAIN = key['AWS_COGNITO_DOMAIN']
    AWS_COGNITO_USER_POOL_ID = key['AWS_COGNITO_USER_POOL_ID']
    AWS_COGNITO_USER_POOL_CLIENT_ID = key['AWS_COGNITO_USER_POOL_CLIENT_ID']
    AWS_COGNITO_USER_POOL_CLIENT_SECRET = key['AWS_COGNITO_USER_POOL_CLIENT_SECRET']
    AWS_COGNITO_REDIRECT_URL = key['AWS_COGNITO_REDIRECT_URL']