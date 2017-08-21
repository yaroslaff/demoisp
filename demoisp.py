#!/usr/bin/env python

from flask import Flask, render_template, request
from flask_oauthlib.provider import OAuth2Provider

app = Flask(__name__)
oauth = OAuth2Provider(app)


@app.route("/")
def index():
    return render_template('index.html')
    
if __name__ == '__main__':
    oauth.init_app(app)
    app.run()    
