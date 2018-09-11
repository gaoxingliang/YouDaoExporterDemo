from flask import Flask, redirect, url_for, session, request, jsonify, render_template
from flask_oauthlib.client import OAuth, OAuthException
import requests
# from flask_sslify import SSLify

from logging import Logger
import uuid
# disable ssl cert check
import ssl
from flask_oauthlib.client import OAuth, prepare_request, http



def net_http_request(uri, headers=None, data=None, method=None):
    '''
    Method for monkey patching 'flask_oauthlib.client.OAuth.http_request'
    This version allows for insecure SSL certificates
    '''
    uri, headers, data, method = prepare_request(
        uri, headers, data, method
    )
    req = http.Request(uri, headers=headers, data=data)
    req.get_method = lambda: method.upper()
    try:
        resp = http.urlopen(req, context=ssl._create_unverified_context())
        content = resp.read()
        resp.close()
        return resp, content
    except http.HTTPError as resp:
        content = resp.read()
        resp.close()
        return resp, content



app = Flask(__name__)
# sslify = SSLify(app)
app.debug = True
app.secret_key = 'development'
oauth = OAuth(app)

# Put your consumer key and consumer secret into a config file
# and don't check it into github!!
microsoft = oauth.remote_app(
    'microsoft',
    #consumer_key='Your microsoft application id. refer the readme',
    #consumer_secret='Your microsoft applicaiton password. refer the readme',
    consumer_key='9f0dab57-9155-41ff-9caa-1f6f607363eb',
    consumer_secret='kblRGFEG69%;zcvhMG220$$',
    request_token_params={'scope': 'offline_access User.Read Notes.Read Notes.Read.All Notes.ReadWrite.CreatedByApp Notes.Create Notes.ReadWrite.All'},
    base_url='https://graph.microsoft.com/v1.0/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://login.microsoftonline.com/common/oauth2/v2.0/token',
    authorize_url='https://login.microsoftonline.com/common/oauth2/v2.0/authorize',

)

microsoft.http_request = net_http_request



@app.route('/')
def index():
    return render_template('hello.html')


@app.route('/login', methods=['POST', 'GET'])
def login():
    if 'microsoft_token' in session:
        return redirect(url_for('me'))

    # Generate the guid to only accept initiated logins
    guid = uuid.uuid4()
    session['state'] = guid

    return microsoft.authorize(callback=url_for('authorized', _external=True), state=guid)


@app.route('/logout', methods=['POST', 'GET'])
def logout():
    session.pop('microsoft_token', None)
    session.pop('state', None)
    return redirect(url_for('index'))

@app.route('/listNotebooks', methods=['GET'])
def listNotebooks():
    headers = {
                #'User-Agent' : 'python_tutorial/1.0',
               'Authorization' : 'Bearer {0}'.format(session['microsoft_token'][0])
               #'Accept' : 'application/json',
               #'Content-Type' : 'application/json'
               }

    request_id = str(uuid.uuid4())
    instrumentation = {'client-request-id' : request_id,
                   'return-client-request-id' : 'true'}
    headers.update(instrumentation)

    url = "https://graph.microsoft.com/v1.0/me/onenote/notebooks"
    response = requests.get(url=url,headers=headers)
    print(response)
    return redirect(url_for('index'))




@app.route('/login/authorized')
def authorized():
    response = microsoft.authorized_response()

    if response is None:
        return "Access Denied: Reason=%s\nError=%s" % (
            response.get('error'),
            request.get('error_description')
        )

    # Check response for state
    print("Response: " + str(response))
    if str(session['state']) != str(request.args['state']):
        raise Exception('State has been messed with, end authentication')

    # Okay to store this in a local variable, encrypt if it's going to client
    # machine or database. Treat as a password.
    session['microsoft_token'] = (response['access_token'], '')

    return redirect(url_for('me'))


@app.route('/me')
def me():
    me = microsoft.get('me')
    return render_template('me.html', me=str(me.data))


# If library is having trouble with refresh, uncomment below and implement refresh handler
# see https://github.com/lepture/flask-oauthlib/issues/160 for instructions on how to do this

# Implements refresh token logic
# @app.route('/refresh', methods=['POST'])
# def refresh():

@microsoft.tokengetter
def get_microsoft_oauth_token():
    return session.get('microsoft_token')


if __name__ == '__main__':
    app.run(host='127.0.0.1', ssl_context='adhoc')
