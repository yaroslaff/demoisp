#!/usr/bin/env python

from flask import Flask, render_template, request, session, g
import flask
from flask_oauthlib.provider import OAuth2Provider
from flask_login import LoginManager, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy

#from models import User

import sqlite3
import json
import random
import string
import sys
import requests
from datetime import datetime, timedelta


DATABASE='demoisp.db'
VERSION='1.1'

app = Flask(__name__)
oauth = OAuth2Provider(app)
oauth.init_app(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

app.secret_key = 'super secret key'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///demoisp.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['OAUTH2_PROVIDER_ERROR_URI'] = '/oauth/errors'
app.config['OAUTH2_PROVIDER_ERROR_ENDPOINT'] = '/oauth/errors'
app.config['OAUTH2_PROVIDER_TOKEN_EXPIRES_IN'] = 3600


db = SQLAlchemy(app)

############## MODELS

##### USER

class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(120), unique=True)
    is_active = db.Column(db.Boolean, default=False, nullable=False)    
    is_authenticated = False
           
    def __init__(self, name, email):
        self.username = name
        self.email = email
        self.password = ''
        self.is_authenticated = True
        self.is_active = True
        self.is_anonymous  = False
    
    def __repr__(self):
        return "user {}".format(self.username)
    
    def get_id(self):
        return self.username



##### OAUTH2

class Client(db.Model):
    # human readable name, not required
    name = db.Column(db.String(40))

    # human readable description, not required
    description = db.Column(db.String(400))

    # creator of the client, not required
    user_id = db.Column(db.ForeignKey('user.id'))
    # required if you need to support client credential
    user = db.relationship('User')

    client_id = db.Column(db.String(40), primary_key=True)
    client_secret = db.Column(db.String(55), unique=True, index=True,
                              nullable=False)

    # public or confidential
    is_confidential = db.Column(db.Boolean)

    _redirect_uris = db.Column(db.Text)
    _default_scopes = db.Column(db.Text)

    @property
    def client_type(self):
        if self.is_confidential:
            return 'confidential'
        return 'public'

    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris.split()
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    @property
    def default_scopes(self):
        if self._default_scopes:
            return self._default_scopes.split()
        return []


class Grant(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = db.relationship('User')

    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id'),
        nullable=False,
    )
    client = db.relationship('Client')

    code = db.Column(db.String(255), index=True, nullable=False)

    redirect_uri = db.Column(db.String(255))
    expires = db.Column(db.DateTime)

    _scopes = db.Column(db.Text)

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []

class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id'),
        nullable=False,
    )
    client = db.relationship('Client')

    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id')
    )
    user = db.relationship('User')

    # currently only bearer is supported
    token_type = db.Column(db.String(40))

    access_token = db.Column(db.String(255), unique=True)
    refresh_token = db.Column(db.String(255), unique=True)
    expires = db.Column(db.DateTime)
    _scopes = db.Column(db.Text)

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []
        

############### HELPER FUNCTIONS
     
@login_manager.user_loader
def load_user(username, password=None):
    if password is None:    
        user = User.query.filter_by(username=username).first()
    else:
        user = User.query.filter_by(username=username, password=password).first()

    if user:
        user.is_authenticated = True
        user.is_active = True
        user.is_anonymous  = False
    return user


@oauth.clientgetter
def load_client(client_id):
    return Client.query.filter_by(client_id=client_id).first()


@oauth.grantgetter
def load_grant(client_id, code):
    return Grant.query.filter_by(client_id=client_id, code=code).first()


@oauth.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):
    # decide the expires time yourself
    expires = datetime.utcnow() + timedelta(seconds=100)
    grant = Grant(
        client_id=client_id,
        code=code['code'],
        redirect_uri=request.redirect_uri,
        _scopes=' '.join(request.scopes),
        user=get_current_user(),
        expires=expires
    )
    db.session.add(grant)
    db.session.commit()
    return grant

def get_current_user():
    return load_user(session['user_id'])
        
@oauth.tokengetter
def load_token(access_token=None, refresh_token=None):
    if access_token:
        return Token.query.filter_by(access_token=access_token).first()
    elif refresh_token:
        return Token.query.filter_by(refresh_token=refresh_token).first()


@oauth.tokensetter
def save_token(token, request, *args, **kwargs):
    toks = Token.query.filter_by(client_id=request.client.client_id,
                                 user_id=request.user.id)
    # make sure that every client has only one token connected to a user
    for t in toks:
        db.session.delete(t)

    expires_in = token.get('expires_in')
    expires = datetime.utcnow() + timedelta(seconds=expires_in)

    tok = Token(
        access_token=token['access_token'],
        refresh_token=token['refresh_token'],
        token_type=token['token_type'],
        _scopes=token['scope'],
        expires=expires,
        client_id=request.client.client_id,
        user_id=request.user.id,
    )
    db.session.add(tok)
    db.session.commit()
    return tok


def get_server(partner_id):

    cr = requests.get('https://cp.okerr.com/api/partner/check/{}'.format(partner_id), auth=('demoisp','demoisppass'))
    if cr.status_code != 200:
        raise ValueError('{}: {}'.format(cr.status_code, cr.text))
    data = json.loads(cr.text)
    return data['server']
    
######  VIEWS

@app.route('/oauth/authorize', methods=['GET', 'POST'])
@login_required
@oauth.authorize_handler
def authorize(*args, **kwargs):
    return True
    
@app.route('/oauth/token', methods=['POST'])
@oauth.token_handler
def access_token():
    return None


@app.route('/oauth/revoke', methods=['POST'])
@oauth.revoke_handler
def revoke_token(): pass

@app.route("/oauth/errors")
def oauth_errors():
    print("oauth errors")
    page = "Error: {}<br>Description: {}<br>".format(request.args.get('error','<unknown>'), request.args.get('error_description','<unknown>'))
    return page
    
@app.route("/api/profile")
# @login_required
@oauth.require_oauth('profile')
def profile():
    d = dict()

    user = request.oauth.user

    d['username'] = user.username
    d['email'] = user.email
    
    return json.dumps(d, indent=4)

@app.route("/info")
def info():
    d = {
            'version': VERSION
        }
    return json.dumps(d, indent=4)

@app.route("/")
@login_required
def index():
            
    if request.headers.get('x-forwarded-proto',None) == 'http':
        url = request.url.replace('http://', 'https://', 1)
        code = 301
        return flask.redirect(url, code=code)
    
    
    puser = 'demoisp'
    ppass = 'demoisppass'
    
    try:
        server = get_server(1)
    except ValueError as e:
        return repr(e)
    
    
    cr = requests.get('{}api/partner/check/1'.format(server), auth=('demoisp','demoisppass'))    
    data = json.loads(cr.text)
    
    resp = flask.make_response(render_template('index.html', data=data))


    if request.headers.get('x-forwarded-proto',None) == 'https':
        resp.headers['Strict-Transport-Security'] = "max-age=31536000; includeSubDomains"

    return resp


@app.route("/admin", methods=['GET', 'POST'])
@login_required
def admin():
            
    if request.headers.get('x-forwarded-proto',None) == 'http':
        url = request.url.replace('http://', 'https://', 1)
        code = 301
        return flask.redirect(url, code=code)
    
    auth = ('demoisp', 'demoisppass')        
    try:
        server = get_server(1)
    except ValueError as e:
        return repr(e)


    if 'revgroup' in request.form:
        gname = request.form['revgroup']
        exp = request.form['exp']
        data = {'group': gname, 'exp': exp, 'partner_id': 1}
        
        r = requests.post('{}api/partner/revoke'.format(server), auth=auth, data=data)
        
        return flask.redirect(request.url)


    if 'addgroup' in request.form:
        gname = request.form['addgroup']
        data = {'group': gname, 'partner_id': 1}
        if gname.startswith('perk'):
            data['new'] = 1
        
        r = requests.post('{}api/partner/grant'.format(server), auth=auth, data=data)
        
        return flask.redirect(request.url)

    

    cr = requests.get('{}api/partner/check/1'.format(server), auth=auth)    
    data = json.loads(cr.text)
    
    
    cr = requests.get('{}api/groups'.format(server))    
    groups = json.loads(cr.text)
    glist = list()

    for gname in sorted(groups.keys()):
        ginfo = groups[gname]
        ginfo['_name'] = gname
        glist.append(ginfo)

    resp = flask.make_response(render_template('admin.html', groups=glist, data=data))

    if request.headers.get('x-forwarded-proto',None) == 'https':
        resp.headers['Strict-Transport-Security'] = "max-age=31536000; includeSubDomains"

    return resp



    
@app.route('/login', methods=['GET', 'POST'])
def login():

            
    if request.headers.get('x-forwarded-proto',None) == 'http':
        url = request.url.replace('http://', 'https://', 1)
        code = 301
        return flask.redirect(url, code=code)



    # Here we use a class of some kind to represent and validate our
    # client-side form data. For example, WTForms is a library that will
    # handle this for us, and we use a custom LoginForm to validate.
    
    if 'user' in request.form:
        
        if request.form.get('user',default='') and request.form.get('password', default=''):
            # Login and validate the user.
            # user should be an instance of your `User` class
            #login_user(user)

        
            user = load_user(request.form['user'], request.form['password'])
            
            if user is None:
                flask.flash('Bad login/pass')
                return render_template('login.html', error='Bad login/pass')

            login_user(user)

            # flask.flash('Logged in successfully.')

            return flask.redirect(flask.url_for('index'))
        else:
            flask.flash('Bad login/pass')
            return render_template('login.html', error='Bad login/pass')


    resp = flask.make_response(render_template('login.html'))

    if request.headers.get('x-forwarded-proto',None) == 'https':
        resp.headers['Strict-Transport-Security'] = "max-age=31536000; includeSubDomains"
        
    return resp

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return flask.redirect(flask.url_for('index'))


def id_generator(size=6, chars=string.ascii_uppercase + string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


def show():
    client = Client.query.filter_by(name='okerr').first()
    
    if client is None:
        print("no client")
        
    print("client:", client.name)
    for ru in client._redirect_uris.split():
        print(ru)


def init_client():

    hostnames = ['echo.okerr.com', 'bravo.okerr.com', 'charlie.okerr.com','cp.okerr.com']
    ruris = ['https://cp.okerr.com/sredir/dev/oauth2/callback']

    print("init client")

    client = Client.query.filter_by(name='okerr').first()
    
    if client is None:
        client = Client()
        
    client.name = 'okerr'
    client.description = 'okerr monitoring platform'
    
    if not client.client_id:
        client.client_id = id_generator(20, string.digits)
    if not client.client_secret:
        client.client_secret = id_generator(50)
    
    client.is_confidential = True
    client._default_scopes = 'profile'    
    
    for host in hostnames:
        ruris.append('https://{}/oauth2/callback'.format(host))
    
    ruris.append()
    
    for ru in ruris:
        print(ru)    
    client._redirect_uris = ' '.join(ruris)
    db.session.add(client)
    db.session.commit()
    

    
if __name__ == '__main__':
    if "reinit" in sys.argv:
        init_client()
        sys.exit(0)

    if "show" in sys.argv:
        show()
        sys.exit(0)


    if "info" in sys.argv:
        print(info())
        sys.exit(0)

    app.run()    
    
    
