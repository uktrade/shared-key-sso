import os
import datetime as dt
import hashlib
import logging
from urllib.parse import urljoin, quote_plus

from flask import Flask, redirect, url_for, session, request, jsonify
from flask_oauthlib.client import OAuth

from dotenv import load_dotenv
from raven.contrib.flask import Sentry

dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(dotenv_path)

SHARED_KEY = os.getenv('SHARED_KEY')
APPLICATION_URL = os.getenv('APPLICATION_URL')
ABC_CLIENT_ID = os.getenv('ABC_CLIENT_ID')
ABC_CLIENT_SECRET = os.getenv('ABC_CLIENT_SECRET')
ABC_BASE_URL = os.getenv('ABC_BASE_URL')
ABC_TOKEN_URL = urljoin(ABC_BASE_URL, '/o/token/')
ABC_AUTHORIZE_URL = urljoin(ABC_BASE_URL, '/o/authorize/')

PORT = os.getenv('PORT', 5000)

logger = logging.getLogger(__name__)
sentry = Sentry(app, dsn=os.getenv('SENTRY_DSN'))

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
app.debug = os.getenv('DEBUG') == 'True'
oauth = OAuth(app)

abc = oauth.remote_app(
   'abc',
   base_url=ABC_BASE_URL,
   request_token_url=None,
   access_token_url=ABC_TOKEN_URL,
   authorize_url=ABC_AUTHORIZE_URL,
   consumer_key=ABC_CLIENT_ID,
   consumer_secret=ABC_CLIENT_SECRET,
   access_token_method='POST'
)


def _generate_shared_key_url(email):
    ts = dt.datetime.now().strftime('%Y%m%d%H%M%S')

    hash = hashlib.sha256(
        SHARED_KEY.encode('utf-8') +
        ts.encode('utf-8') +
        email.encode('utf-8')
    ).hexdigest()

    return APPLICATION_URL.format(
        email=quote_plus(email),
        timestamp=ts,
        hash=hash
    )


def _get_email():
    """Get the user's email from their profile"""

    if 'abc_token' in session:
        me = abc.get('/api/v1/user/me/')
        if me.status != 200:
            return None

        return me.data["email"]

    return None


@app.route('/')
def index():
    return redirect(url_for('cyber'))


@app.route('/cyber')
def cyber():
    email = _get_email()

    if not email:
        return redirect(url_for('login'))
    else:
        return redirect(_generate_shared_key_url(email))


@app.route('/login')
def login():
    return abc.authorize(callback=url_for('authorized', _external=True))


@app.route('/logout')
def logout():
    session.pop('abc_token', None)
    return redirect(url_for('cyber'))


@app.route('/login/authorized')
def authorized():
    # TODO: Test failed auth flow, e.g ?error=access-denied
    # it should handle this situation correctly
    resp = abc.authorized_response()
    if resp is None or resp.get('access_token') is None:
        return 'Access denied: reason=%s error=%s resp=%s' % (
            request.args['error'],
            request.args['error_description'],
            resp)
    session['abc_token'] = (resp['access_token'], '')

    return redirect(url_for('cyber'))


@abc.tokengetter
def get_abc_oauth_token():
    return session.get('abc_token')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT)
