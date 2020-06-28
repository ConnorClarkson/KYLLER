# KYLLER flask-app


## Getting started
Standalone web service:

```shell
pip install -r requirements.txt
python app.py
```

## Prerequisites
Create ./app/static/KEYS \
Create ./app/static/KEYS/aws.json

```shell

{
  "AWS_DEFAULT_REGION": "",
  "AWS_ACCESS_KEY_ID": "",
  "AWS_SECRET_ACCESS_KEY": "",
  "COGNITO_USERPOOL_ID": "",
  "AWS_COGNITO_USER_POOL_ID": "",
  "AWS_COGNITO_USER_POOL_CLIENT_ID": "",
  "COGNITO_REGION": "",
  "AWS_COGNITO_USER_POOL_CLIENT_SECRET": "",
  "AWS_COGNITO_DOMAIN": "",
  "AWS_COGNITO_REDIRECT_URL" : ""
}
```

Visit [http://localhost:5000](http://localhost:5000)
