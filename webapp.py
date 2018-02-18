#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017-2018 Alan Frost. All rights reserved.

Implementation of Web server using Flask framework

"""

from __future__ import print_function

import logging
import signal
import socket
from datetime import datetime
import time
from urlparse import urlparse, urljoin
import pytz
import simplejson as json
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
import jinja2

from botocore.exceptions import EndpointConnectionError, ClientError
from flask import (Flask, make_response, request, render_template, redirect, jsonify,
                   abort, flash, url_for)
from flask_login import (LoginManager, current_user, login_required, login_user, logout_user,
                         fresh_login_required)
from decorators import async
from forms import (AcceptForm, ChangePasswordForm, ConfirmForm, ForgotPasswordForm,
                   InviteForm, LoginForm, RegistrationForm, VerifyForm, ResetPasswordForm,
                   ResendForm, UploadForm)
from crypto import derive_key
from utils import (load_config, generate_timed_token, validate_timed_token, generate_user_id,
                   generate_random58_id, preset_password, generate_random_int,
                   generate_otp_secret, generate_hotp_code, generate_totp_code,
                   verify_hotp_code, verify_totp_code, get_ip_address, get_user_agent)
from awsutils import DynamoDB, SNS, SES, S3
from recipe import RecipeManager
from vault import VaultManager
from events import EventManager

CONFIG = load_config('config.json')

USERS = DynamoDB(CONFIG, CONFIG.get('users'))
SESSIONS = DynamoDB(CONFIG, CONFIG.get('sessions'))
RECIPE_MANAGER = RecipeManager(CONFIG)
RECIPE_MANAGER.load_recipes('recipes.json')
RECIPE_LIST = RECIPE_MANAGER.build_search_list()
VAULT_MANAGER = VaultManager(CONFIG)
EVENT_MANAGER = EventManager(CONFIG)
SNS = SNS('FrostyWeb')
SES = SES('Alan Frost <alan@cyberfrosty.com>')

# Log exceptions and errors to /var/log/cyberfrosty.log
# 2017-05-11 08:29:26,696 ERROR webapp:main [Errno 51] Network is unreachable
LOGGER = logging.getLogger("CyberFrosty")


SERVER_VERSION = '0.1'
SERVER_START = int((datetime.now(tz=pytz.utc) -
                    datetime(1970, 1, 1, tzinfo=pytz.utc)).total_seconds())
MAX_FAILURES = 3
LOCK_TIME = 1800
LOGIN_MANAGER = LoginManager()
APP = Flask(__name__, static_url_path="")

APP.config['SECRET_KEY'] = 'super secret key'
APP.config['SSL_DISABLE'] = False
APP.config['SESSION_COOKIE_HTTPONLY'] = True
APP.config['REMEMBER_COOKIE_HTTPONLY'] = True
APP.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # Limit uploads to 16MB

LOGIN_MANAGER.init_app(APP)
LOGIN_MANAGER.login_view = "login"
LOGIN_MANAGER.login_message = "Please login to access this page"
LOGIN_MANAGER.session_protection = "strong"
CSRF = CSRFProtect(APP)

@async
def send_email(recipient, subject, action, **kwargs):
    """ Send an email from a new thread
    Args:
        recipient
        email subject line
        action template
        arguments for templating
    """
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('./templates'))
    template = env.get_template('email/' + action + '.txt')
    text = template.render(**kwargs)
    template = env.get_template('email/' + action + '.html')
    html = template.render(title=subject, **kwargs)

    with APP.app_context():
        try:
            SES.send_email(recipient, subject, html, text)
        except ClientError as err:
            print(err.response['Error']['Message'])

@async
def send_text(phone, msg):
    """ Send a text message from a new thread
    Args:
        number: phone number (e.g. '+17702233322')
        message: text
    """
    #with APP.app_context():
    #    try:
    #        SNS.send_sms(phone, msg)
    #    except ClientError as err:
    #        print(err.response['Error']['Message'])
    print(msg)

class User(object):
    """ Class for the current user
    """
    def __init__(self, email, user=None):
        """ Constructor
        """
        self._email = email
        self._userid = generate_user_id(CONFIG.get('user_id_hmac'), email)
        self._user = user
        self._authenticated = False
        self._active = False

    @property
    def is_authenticated(self):
        return self._authenticated

    @is_authenticated.setter
    def is_authenticated(self, value):
        self._authenticated = value

    @property
    def is_active(self):
        return self._active

    @is_active.setter
    def is_active(self, value):
        self._active = value

    def generate_token(self, action):
        """ Generate a timed token, tied to user name and action
        Args:
            action: confirm, delete, register, reset, etc.
        Return:
            URL safe encoded token
        """
        return generate_timed_token(self._email, APP.config['SECRET_KEY'], action)

    def validate_token(self, token, action):
        """ Validate a timed token, tied to user name and action
        Args:
            token
            action: confirm, delete, register, reset, etc.
        Return:
            True or False
        """
        validated, value = validate_timed_token(token, APP.config['SECRET_KEY'], action)
        if validated and value == self._email:
            return True
        return False

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return self._userid

    def get_email(self):
        return self._email

    def get_user(self):
        return self._user

@LOGIN_MANAGER.user_loader
def load_user(userid):
    """ Load user account details from database
    Args:
        userid
    """
    session = SESSIONS.get_item('id', userid)
    if 'error' in session:
        account = USERS.get_item('id', userid)
        if 'error' not in account:
            name = account.get('user')
            print('Loaded user: {}'.format(account.get('email')))
            user = User(account.get('email'), name)
        else:
            print('Anonymous user')
            user = User('anonymous@unknown.com', 'Anonymous')
            user.is_authenticated = False
            user.is_active = False
    else:
        name = session.get('user')
        print('Loaded session: {}'.format(session.get('email')))
        user = User(session.get('email'), name)
        user.is_authenticated = session.get('failures', 0) < MAX_FAILURES
        user.is_active = True
    return user

@LOGIN_MANAGER.unauthorized_handler
def unauthorized_page():
    """ Called when @login_required decorator triggers, redirects to login page and after
        success redirects back to referring page
    """
    return redirect(url_for('login') + '?next=' + request.path)

def get_parameter(response, param, default=None):
    """ Get named parameter from url, json or either of two types of form encoding
    Args:
        response: dictionary of HTTP response
        param: key to look for
    Returns:
        value or parameter or None
    """
    value = response.args.get(param)
    if not value and response.json:
        value = response.json.get(param)
    if not value:
        content_type = response.headers.get('Content-Type')
        if content_type:
            if content_type == 'application/x-www-form-urlencoded' or \
               content_type.startswith('multipart/form-data'):
                value = response.form.get(param)
    if not value:
        return default
    else:
        return value

def is_safe_url(target):
    """ Ensure that the redirect URL refers to the same host and not to an attackers site.
    Args:
        target url
    Returns:
        True if target url is safe
    """
    # Check for open redirect vulnerability, which allows ///host.com to be parsed as a path
    if '///' in target:
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

def get_redirect_target():
    """ Look for the 'next' parameter or use the request object to find the redirect target.
        This function is used for login and other actions where after success the user is
        redirected back to the page, from which they were redirected to login first.
    Returns:
        redirect URL or None
    """
    for target in get_parameter(request, 'next'), request.referrer:
        if target and is_safe_url(target):
            return target

def redirect_back(endpoint, **values):
    """ Redirect back to next url, if missing or not safe defaults to endpoint url
    Args:
        endpoint url
        value parameters
    """
    target = get_parameter(request, 'next')
    if not target or not is_safe_url(target):
        target = url_for(endpoint, **values)
    return redirect(target)

def allowed_file(filename):
    """ Only allow specific file types to be uploaded
    Args:
        filename
    Returns:
        True if file type is allowed
    """
    extensions = set(['csv', 'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in extensions

def failed_account_attempt(session, failures, failmsg=None):
    """ Handle a failed attempt (login, accept, confirm, change...)
    Args:
        session object
        failure count
        optional fail message
    Returns:
        True if file type is allowed
    """
    failures += 1
    if 'error' in session: # An error means no session entry exists
        del session['error']
        session['failures'] = 1
        SESSIONS.put_item(session)
        errmsg = 'Unable to validate your credentials'
    elif failures > MAX_FAILURES:
        session['locked_at'] = int(time.mktime(datetime.utcnow().timetuple()))
        session['failures'] = failures
        SESSIONS.put_item(session)
        errmsg = 'Your account has been locked'
    else:
        SESSIONS.update_item('id', session.get('id'), 'failures', failures)
        errmsg = failmsg or 'Unable to validate your credentials'
    return errmsg

def check_account_lock(session):
    """ Check for an account lock and return the appropriate number of failures
    Args:
        session object
    Returns:
        correct failure count
    """
    failures = session.get('failures', 0)
    if failures > MAX_FAILURES:
        if 'locked_at' in session:
            locktime = int(time.mktime(datetime.utcnow().timetuple())) - session['locked_at']
            if locktime > LOCK_TIME:
                failures = MAX_FAILURES  # Locked time expired, reset failure counter for one chance
        else:
            SESSIONS.update_item('id', session.get('id'),
                                 'locked_at', int(time.mktime(datetime.utcnow().timetuple())))
    return failures

@APP.errorhandler(400)
def bad_request(error):
    """ Handle HTTP Bad Request error
    """
    if error.description:
        return make_response(jsonify({'error': str(error.description)}), 400)
    else:
        return make_response(jsonify({'error': str(error)}), 400)

@APP.errorhandler(401)
def unauthorized(error):
    """ Handle HTTP Unauthorized error
    """
    if error.description:
        return make_response(jsonify({'error': str(error.description)}), 401)
    else:
        return make_response(jsonify({'error': str(error)}), 401)

@APP.errorhandler(403)
def forbidden(error):
    """ Handle HTTP Forbidden error
    """
    if error.description:
        return make_response(jsonify({'error': str(error.description)}), 403)
    else:
        return make_response(jsonify({'error': str(error)}), 403)

@APP.errorhandler(404)
def not_found(error):
    """ Handle HTTP Not Found error
    """
    if error.description:
        return make_response(jsonify({'error': str(error.description)}), 404)
    else:
        return make_response(jsonify({'error': str(error)}), 404)

@APP.errorhandler(405)
def not_allowed(error):
    """ Handle HTTP Method Not Allowed error
    """
    if error.description:
        return make_response(jsonify({'error': str(error.description)}), 405)
    else:
        return make_response(jsonify({'error': str(error)}), 405)

@APP.errorhandler(409)
def resource_exists(error):
    """ Handle HTTP Conflict error
    """
    if error.description:
        return make_response(jsonify({'error': str(error.description)}), 409)
    else:
        return make_response(jsonify({'error': str(error)}), 409)

@APP.errorhandler(422)
def unprocessable_entity(error):
    """ Handle HTTP Unprocessable entity error
    """
    if error.description:
        return make_response(jsonify({'error': str(error.description)}), 422)
    else:
        return make_response(jsonify({'error': str(error)}), 422)

@APP.errorhandler(500)
def server_error(error):
    """ Handle HTTP Server error
    """
    if 'description' in error:
        return make_response(jsonify({'error': str(error.description)}), 500)
    else:
        return make_response(jsonify({'error': str(error)}), 500)

@APP.route('/google3dd7b0647e1f4d7a.html')
def google_site_verify():
    """ Google site verification
    """
    return render_template('google3dd7b0647e1f4d7a.html')

@APP.route('/')
@APP.route('/index')
def index():
    """ Show main landing page
    """
    return render_template('index.html', search=RECIPE_LIST)

@APP.route('/api/server.info')
def server_info():
    """ Return server status information
    """
    url_fields = urlparse(request.url)
    timestamp = int((datetime.now(tz=pytz.utc) -
                     datetime(1970, 1, 1, tzinfo=pytz.utc)).total_seconds())
    uptime = time.strftime("%H:%M:%S", time.gmtime(timestamp - SERVER_START))
    return jsonify({'server': url_fields.netloc, 'version': SERVER_VERSION, 'uptime': uptime})

@APP.route('/recipes', methods=['GET'])
def recipes():
    """ Show recipes
    """
    if current_user.is_authenticated:
        userid = current_user.get_id()
    else:
        userid = get_ip_address(request)

    recipe = request.args.get('recipe')
    if recipe is not None:
        EVENT_MANAGER.web_event('recipes', userid, **{"recipe": recipe})
        html = RECIPE_MANAGER.get_rendered_recipe(recipe)
        return render_template('recipes.html', search=RECIPE_LIST, recipe=html, title=recipe)
    else:
        EVENT_MANAGER.web_event('recipes', userid)
        html = RECIPE_MANAGER.get_latest_recipe()
        return render_template('recipes.html', search=RECIPE_LIST, recipe=html)

@APP.route('/gallery')
def gallery():
    """ Show gallery
    """
    category = request.args.get('category')
    html = RECIPE_MANAGER.get_rendered_gallery(category)
    if category:
        search = RECIPE_MANAGER.build_search_list(category)
    else:
        search = RECIPE_LIST
    return render_template('gallery.html', search=search, gallery=html)

@APP.route('/upload', methods=['GET', 'POST'])
#@login_required
def upload():
    """ Upload an image with metadata
    """
    userid = generate_user_id(CONFIG.get('user_id_hmac'), current_user.get_email())
    account = USERS.get_item('id', userid)
    if not account or 'error' in account:
        return redirect(url_for('register', email=current_user.get_email()))
    if 'bucket' not in account:
        return redirect(url_for('profile', email=current_user.get_email()))
    path = userid + '/'
    form = UploadForm()
    if form.validate_on_submit():
        content_type = request.headers.get('Content-Type')
        if not (content_type and content_type.startswith('multipart/form-data')):
            abort(400, 'Missing or unsupported content type for upload')
        print(request.files['file'])
        # Handle multipart form encoded data
        if request.method == 'POST':
            content = request.files['file']
            if not content:
                abort(400, 'No file content for upload')
            if content.filename == '':
                abort(400, 'No file selected for upload')
            if not allowed_file(content.filename):
                abort(400, 'Unsupported file type for upload')
            path += secure_filename(content.filename)
            #params = {'file':content.filename, 'filename':path, 'identifier':group}

        if form.tags.data:
            tags = [tag.strip() for tag in form.tags.data.lower().split(',')]
        else:
            tags = []
        metadata = {'title': form.title.data,
                    'artform': form.artform.data,
                    'created': form.created.data,
                    'dimensions': form.dimensions.data,
                    'path': path,
                    'tags': tags}
        print(json.dumps(metadata))
        aws3 = S3()
        response = aws3.upload_data(content, account['bucket'], path)
        if 'error' in response:
            abort(400, response['error'])
    return render_template('upload.html', form=form)

@APP.route('/messages')
@login_required
def messages():
    """ Show messages
    """
    return render_template('messages.html')

@APP.route('/vault', methods=['GET', 'PATCH', 'POST', 'PUT'])
@fresh_login_required
def vault():
    """ Get or update the vault contents
    """
    userid = generate_user_id(CONFIG.get('user_id_hmac'), current_user.get_email())
    myvault = VAULT_MANAGER.get_vault(userid)
    if request.method == 'GET':
        if 'error' in myvault:
            html = VAULT_MANAGER.get_rendered_vault(None)
            mcf = '<div hidden id="mcf" />'
        else:
            mcf = '<div hidden id="mcf">' + myvault.get('mcf', '') + '</div>'
            box = request.args.get('box')
            if box is not None:
                mybox = myvault[box]
                html = '<div hidden id="safebox">' + json.dumps(mybox) + '</div>\n'
                html += '<div id="safebox-table"></div>\n'
            else:
                html = VAULT_MANAGER.get_rendered_vault(myvault)
        return render_template('vault.html', contents=html, mcf=mcf)

    elif request.method == 'PATCH' or request.method == 'PUT':
        if not request.json:
            abort(400, 'Invalid input, json expected')
        if 'error' in myvault:
            abort(404, myvault['error'])
        for key in myvault.keys():
            if key in request.json:
                myvault[key]['contents'] = request.json[key]
                response = VAULT_MANAGER.post_vault(userid, myvault)
                if 'error' in response:
                    abort(422, response['error'])
                return jsonify(response)

    elif request.method == 'POST':
        if not request.json:
            abort(400, 'Invalid input, json expected')
        if 'error' not in myvault:
            abort(409, 'Vault already exists')
        mcf = request.json.get('mcf')
        box = request.json.get('box')
        columns = request.json.get('columns')
        contents = request.json.get('contents') or ''
        title = request.json.get('title')
        icon = request.json.get('icon')
        if not mcf or not box or not columns or not isinstance(columns, list):
            abort(422, 'Missing box, columns or mcf')
        if not title:
            title = box[:1].upper() + box[1:]
        if not icon:
            icon = 'fa-key'
        myvault = {"mcf": mcf,
                   box: {"title": title, "icon": icon, "columns": columns, "contents": contents}}
        response = VAULT_MANAGER.post_vault(userid, myvault)
        if 'error' in response:
            abort(422, response['error'])
        return jsonify(response)

@APP.route('/privacy', methods=['GET'])
def privacy():
    """ Show privacy policy
    """
    return render_template('privacy.html')

@APP.route("/accept", methods=['GET', 'POST'])
def accept():
    """ Accept account invitation with emailed token and optional SMS code
    """
    errmsg = None
    form = AcceptForm()
    # GET - populate form with confirmation data
    if request.method == 'GET':
        email = get_parameter(request, 'email')
        token = get_parameter(request, 'token')
        action = get_parameter(request, 'action')
        if email is None or action is None or token is None:
            errmsg = 'Missing or invalid invitation'
        else:
            form.email.data = email
            form.token.data = token
            form.action.data = action
            validated, value = validate_timed_token(token, APP.config['SECRET_KEY'], action)
            if not validated or value != email:
                errmsg = 'The invitation link is invalid or has expired'
            else:
                userid = generate_user_id(CONFIG.get('user_id_hmac'), email)
                account = USERS.get_item('id', userid)
                if not account or 'error' in account:
                    errmsg = 'Unable to validate your credentials'
                else:
                    form.user.data = account.get('user')
                    form.phone.data = account.get('phone')
        if errmsg:
            form.errors['Accept'] = [errmsg]
            agent = {"ip": get_ip_address(request), "from": get_user_agent(request)}
            EVENT_MANAGER.error_event('accept', email, errmsg, **agent)

    # POST - validate form data
    elif form.validate_on_submit():
        action = form.action.data
        email = form.email.data
        token = form.token.data
        user = form.user.data
        phone = form.phone.data
        agent = {"ip": get_ip_address(request), "from": get_user_agent(request)}
        userid = generate_user_id(CONFIG.get('user_id_hmac'), email)
        account = USERS.get_item('id', userid)
        if not account or 'error' in account:
            errmsg = 'Unable to validate your credentials'
            form.token.data = ''
        else:
            # See if there is an existing session (as is the case of an accept failure)
            session = SESSIONS.get_item('id', userid)
            if 'error' in session: # An error means no session entry exists
                session['id'] = userid
                session['email'] = email
                session['user'] = user

            failures = check_account_lock(session)
            session['failures'] = failures
            if failures > MAX_FAILURES:
                errmsg = 'Your account is locked'
        if errmsg:
            form.errors['Confirm'] = [errmsg]
            EVENT_MANAGER.error_event('confirm', userid, form.errors['Confirm'], **agent)
            return render_template('confirm.html', form=form)

        validated, value = validate_timed_token(token, APP.config['SECRET_KEY'], action)
        if validated and value == email:
            old_mcf = account.get('mcf')
            mcf = derive_key(form.oldpassword.data.encode('utf-8'), old_mcf)
            if mcf != old_mcf:
                errmsg = 'Unable to validate your credentials'
            else:
                mcf = derive_key(form.password.data.encode('utf-8'))
                response = USERS.update_item('id', userid, 'mcf', mcf)

            if not errmsg and 'otp' in account:
                code = form.code.data
                fields = account['otp'].split(':')
                secret = fields[0].encode('utf-8')
                counter = int(fields[1])
                code = code.encode('utf-8')
                counter = verify_hotp_code(secret, code, counter)
                if counter is None:
                    errmsg = 'The confirmation code is invalid or has expired'
                    form.token.data = ''
                    if 'error' in session: # An error means no session entry exists
                        del session['error']
                        session['failures'] = 1
                        SESSIONS.put_item(session)
                    else:
                        SESSIONS.update_item('id', userid, 'failures', failures + 1)
                elif counter != int(fields[1]):
                    response = USERS.update_item('id', userid, 'otp', secret + ':' + str(counter))

            # Update user account status and name/phone if changed from invite
            if not errmsg:
                if user != account.get('user'):
                    response = USERS.update_item('id', userid, 'user', user)
                    if 'error' in response:
                        print(response['error'])
                if phone != account.get('phone'):
                    response = USERS.update_item('id', userid, 'phone', phone)
                created = 'confirmed: ' + datetime.utcnow().strftime('%Y-%m-%d')
                response = USERS.update_item('id', userid, 'created', created)
                if 'error' in response:
                    print(response['error'])

                # Login user (they've entered password, code and changed password)
                agent['at'] = datetime.today().ctime()
                if 'error' in session: # An error means no session entry exists
                    del session['error']
                    session['logins'] = agent
                    SESSIONS.put_item(session)
                else:
                    SESSIONS.update_item('id', userid, 'logins', agent)
                username = account.get('user')
                user = User(email, username)
                user.is_authenticated = True
                user.is_active = True
                login_user(user, remember=False)

                flash('You have confirmed your account. Thanks!')
                EVENT_MANAGER.web_event('accept', userid, **agent)
                return redirect(url_for('profile'))
        else:
            failmsg = 'The invitation link is invalid or has expired'
            errmsg = failed_account_attempt(session, failures, failmsg)

        if errmsg:
            form.oldpassword.data = ''
            form.password.data = ''
            form.confirm.data = ''
            form.errors['Accept'] = [errmsg]
            EVENT_MANAGER.error_event('accept', userid, errmsg, **agent)
            return render_template('accept.html', form=form)

    title = 'Accept Invitation'
    return render_template('accept.html', form=form, title=title)

@APP.route("/confirm", methods=['GET', 'POST'])
def confirm():
    """ Confirm user account or action (delete) with emailed token and optional SMS code
    """
    errmsg = None
    form = ConfirmForm()
    # GET - populate form with confirmation data
    if request.method == 'GET':
        email = get_parameter(request, 'email')
        token = get_parameter(request, 'token')
        action = get_parameter(request, 'action')
        if email is None or action is None or token is None:
            errmsg = 'No confirmation found'
        else:
            form.email.data = email
            form.token.data = token
            form.action.data = action
            validated, value = validate_timed_token(token, APP.config['SECRET_KEY'], action)
            if not validated or value != email:
                errmsg = 'The confirmation link is invalid or has expired'
            else:
                userid = generate_user_id(CONFIG.get('user_id_hmac'), email)
                account = USERS.get_item('id', userid)
                if not account or 'error' in account:
                    errmsg = 'Unable to validate your credentials'
        if errmsg:
            form.errors['Confirm'] = [errmsg]
            agent = {"ip": get_ip_address(request), "from": get_user_agent(request)}
            EVENT_MANAGER.error_event('confirm', email, errmsg, **agent)

    # POST - validate form data
    elif form.validate_on_submit():
        action = form.action.data
        email = form.email.data
        token = form.token.data
        agent = {"ip": get_ip_address(request), "from": get_user_agent(request)}
        userid = generate_user_id(CONFIG.get('user_id_hmac'), email)
        account = USERS.get_item('id', userid)
        if not account or 'error' in account:
            errmsg = 'Unable to validate your credentials'
        else:
            session = SESSIONS.get_item('id', userid)
            if 'error' in session:
                session['id'] = userid
                session['email'] = email
                session['user'] = account.get('user')

            failures = check_account_lock(session)
            session['failures'] = failures
            if failures > MAX_FAILURES:
                errmsg = 'Your account is locked'
        if errmsg:
            form.token.data = ''
            form.errors['Confirm'] = [errmsg]
            EVENT_MANAGER.error_event('confirm', userid, errmsg, **agent)
            return render_template('confirm.html', form=form)

        validated, value = validate_timed_token(token, APP.config['SECRET_KEY'], action)
        if validated and value == email:
            code = form.code.data
            if 'otp' in account:
                fields = account['otp'].split(':')
                secret = fields[0].encode('utf-8')
                counter = int(fields[1])
                code = code.encode('utf-8')
                counter = verify_hotp_code(secret, code, counter)
                if counter is None:
                    errmsg = 'The confirmation code is invalid or has expired'
                    form.token.data = ''
                    if 'error' in session: # An error means no session entry exists
                        del session['error']
                        session['failures'] = 1
                        SESSIONS.put_item(session)
                    else:
                        SESSIONS.update_item('id', userid, 'failures', failures + 1)
                elif counter != int(fields[1]):
                    response = USERS.update_item('id', userid, 'otp', secret + ':' + str(counter))

            # Update user account status
            if not errmsg and action == 'register' and account['created'][:7] == 'pending':
                created = 'confirmed: ' + datetime.utcnow().strftime('%Y-%m-%d')
                response = USERS.update_item('id', userid, 'created', created)
                flash('You have confirmed your account. Thanks!')
                EVENT_MANAGER.web_event('confirm', userid, **agent)
                return redirect(url_for('login', email=email))
        else:
            failmsg = 'The confirmation link is invalid or has expired'
            errmsg = failed_account_attempt(session, failures, failmsg)

        if errmsg:
            form.token.data = ''
            form.errors['Confirm'] = [errmsg]
            EVENT_MANAGER.error_event('confirm', userid, errmsg, **agent)
            return render_template('confirm.html', form=form)

    if action == 'register':
        title = 'Confirm Account'
    elif action == 'delete':
        title = 'Delete Account'
    else:
        title = 'Confirm'
    return render_template('confirm.html', form=form, title=title)


@APP.route("/login", methods=['GET', 'POST'])
def login():
    """ Login to user account with email and password
    """
    form = LoginForm()
    # GET - populate form with email if passed
    if request.method == 'GET':
        form.email.data = get_parameter(request, 'email')

    # POST - validate form data
    elif form.validate_on_submit():
        # Login and validate the user.
        agent = {"ip": get_ip_address(request), "from": get_user_agent(request)}
        email = form.email.data
        userid = generate_user_id(CONFIG.get('user_id_hmac'), email)
        account = USERS.get_item('id', userid)
        if not account or 'error' in account:
            errmsg = 'Unable to validate your credentials'
            form.errors['Login'] = [errmsg]
            EVENT_MANAGER.error_event('login', email, errmsg, **agent)
            form.password.data = ''
            return render_template('login.html', form=form)
        session = SESSIONS.get_item('id', userid)
        if 'error' in session:
            session['id'] = userid
            session['email'] = email
            session['user'] = account.get('user')

        failures = check_account_lock(session)
        session['failures'] = failures
        if failures > MAX_FAILURES:
            errmsg = 'Your account is locked'
            form.errors['Login'] = [errmsg]
            form.password.data = ''
            EVENT_MANAGER.error_event('login', userid, errmsg, **agent)
            return render_template('login.html', form=form)

        # Check password
        mcf = derive_key(form.password.data.encode('utf-8'), account['mcf'])
        if mcf != account.get('mcf'):
            errmsg = failed_account_attempt(session, failures)
            form.errors['Login'] = [errmsg]
            form.password.data = ''
            EVENT_MANAGER.error_event('login', userid, errmsg, **agent)
            return render_template('login.html', form=form)

        # Reset failed login counter if needed and clear locked
        if failures > 0:
            session['failures'] = 0
            if 'locked_at' in session:
                del session['locked_at']
        EVENT_MANAGER.web_event('login', userid, **agent)
        #logins = session['logins'] or []
        agent['at'] = datetime.today().ctime()
        #logins.append(agent)
        session['logins'] = agent
        if 'error' in session: # An error means no session entry exists
            del session['error']
        SESSIONS.put_item(session)
        username = account.get('user')
        user = User(email, username)
        authentication = account['authentication']
        if authentication == 'password':
            user.is_authenticated = True
            user.is_active = True
            login_user(user, remember=form.remember.data)
            print('validated user')
        elif authentication == 'password:sms':
            target = request.args.get('next')
            if target is None or not is_safe_url(target):
                target = 'index'
            return redirect(url_for('verify') + '?next=' + target)

        return redirect_back('index')
    return render_template('login.html', form=form)

@APP.route("/logout")
@login_required
def logout():
    """ Logout of user account
    """
    SESSIONS.delete_item('id', current_user.get_id())
    EVENT_MANAGER.web_event('logout', current_user.get_id())
    logout_user()
    return redirect(url_for('index'))

@APP.route('/verify', methods=['GET', 'POST'])
@login_required
def verify():
    """ 2FA verification
    """
    form = VerifyForm(request.form)
    email = request.args.get('email')
    form.email.data = email or current_user.get_email()
    userid = generate_user_id(CONFIG.get('user_id_hmac'), current_user.get_email())
    account = USERS.get_item('id', userid)
    if not account or 'error' in account:
        return redirect(url_for('register', email=current_user.get_email()))
    authentication = account['authentication']

    # Send a code to our user when they GET this page
    if request.method == 'GET':
        if authentication == 'password:authy':
            #send_authy_token_request(user.authy_id)
            print('Sent code')
        elif authentication == 'password:sms':
            code = generate_totp_code(account['otp'])
            send_text(account['phone'], code + ' is your Frosty Web code')

    # POST - validate form data
    elif form.validate_on_submit():
        code = form.code.data
        verified = False

        if authentication == 'password:authy':
            if code == '123456':
                verified = True
            #verified = verify_authy_token(user.authy_id, str(user_entered_code)).ok()
        elif authentication == 'password:sms':
            secret = account.get('otp')
            verified = verify_totp_code(secret, code)
            return redirect(url_for('profile'))

        if verified:
            target = request.args.get('next')
            if target is None or not is_safe_url(target):
                target = 'profile'
            return redirect(url_for(target))
        else:
            form.errors['Verify'] = ['Invalid or expired code']

    return render_template('verify.html', form=form)

@APP.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    """ Show user account profile
    """
    userid = generate_user_id(CONFIG.get('user_id_hmac'), current_user.get_email())
    account = USERS.get_item('id', userid)
    if not account or 'error' in account:
        return redirect(url_for('register', email=current_user.get_email()))
    session = SESSIONS.get_item('id', userid)
    if 'logins' in session:
        account['logins'] = session['logins']
    return render_template('profile.html', account=account)

@APP.route("/headlines", methods=['GET', 'POST'])
@login_required
def headlines():
    """ Show headlines
    """
    userid = generate_user_id(CONFIG.get('user_id_hmac'), current_user.get_email())
    account = USERS.get_item('id', userid)
    if not account or 'error' in account:
        return redirect(url_for('register', email=current_user.get_email()))
    return render_template('profile.html', account=account)

@APP.route("/change", methods=['GET', 'POST'])
@login_required
def change():
    """ Change user account password
    """
    form = ChangePasswordForm()
    # GET - populate form with email if passed
    if request.method == 'GET':
        form.email.data = get_parameter(request, 'email') or current_user.get_email()

    # POST - validate form data
    elif form.validate_on_submit():
        agent = {"ip": get_ip_address(request), "from": get_user_agent(request)}
        userid = generate_user_id(CONFIG.get('user_id_hmac'), form.email.data)
        account = USERS.get_item('id', userid)
        old_mcf = account.get('mcf')
        mcf = derive_key(form.oldpassword.data.encode('utf-8'), old_mcf)
        if mcf != old_mcf:
            errmsg = 'Unable to validate your credentials'
            form.errors['Change'] = [errmsg]
            form.oldpassword.data = ''
            form.password.data = ''
            form.confirm.data = ''
            EVENT_MANAGER.error_event('change', userid, errmsg, **agent)
        else:
            mcf = derive_key(form.password.data.encode('utf-8'))
            response = USERS.update_item('id', userid, 'mcf', mcf)
            if 'error' in response:
                form.errors['Change'] = [response['error']]
                EVENT_MANAGER.error_event('change', userid, response['error'], **agent)
            else:
                flash('Your password has been changed')
                EVENT_MANAGER.web_event('change', userid, **agent)
                return redirect(url_for('profile'))
    return render_template('change.html', form=form)

@APP.route("/resend", methods=['GET', 'POST'])
def resend():
    """ Regenerate and send a new token and/or code
    """
    form = ResendForm()
    # GET - populate form with email if passed
    if request.method == 'GET':
        if current_user.is_authenticated:
            email = current_user.get_email()
        else:
            email = request.args.get('email')
        action = request.args.get('action')
        if email is None or action is None:
            errmsg = 'No action or email found'
        else:
            form.email.data = email
            form.action.data = action

    # POST - validate form data
    elif form.validate_on_submit():
        email = form.email.data
        action = form.action.data
        userid = generate_user_id(CONFIG.get('user_id_hmac'), email)
        account = USERS.get_item('id', userid)
        if not account or 'error' in account:
            errmsg = 'Unable to validate your credentials'
        else:
            token = generate_timed_token(email, APP.config['SECRET_KEY'], action)
            link = url_for(action, email=email, token=token, action=action, _external=True)
            EVENT_MANAGER.web_event('resend', userid, **{action: action})
            user = account.get('user') or email
            if action == 'invite':
                intro = 'You have requested a new {} token.'.format(action)
                send_email(email, 'Resend Token', 'resend',
                           user=user, intro=intro, token=token, link=link)
                flash('A new confirmation code has been sent to ' + email)
                return redirect(url_for('confirm', email=email, action=action))
            #elif form.action.data == 'verify':

    if errmsg:
        form.errors['Resend'] = [errmsg]
        agent = {"ip": get_ip_address(request), "from": get_user_agent(request)}
        EVENT_MANAGER.error_event('resend', email, errmsg, **agent)

    return render_template('resend.html', form=form)

@APP.route("/invite", methods=['GET', 'POST'])
@login_required
def invite():
    """ Invite a new user to join by providing an email address and phone number for them.
        An invitation is emailed to the user with a temporary password and a one time code
        is sent via text message to the phone number.
    """
    form = InviteForm()
    if form.validate_on_submit():
        email = form.email.data
        user = form.user.data
        phone = form.phone.data
        userid = generate_user_id(CONFIG.get('user_id_hmac'), email)
        account = USERS.get_item('id', userid)
        if account and 'error' not in account:
            errmsg = 'Email address already in use'
            form.errors['Invite'] = [errmsg]
            EVENT_MANAGER.error_event('invite', current_user.get_id(), errmsg, **{"email": email})
            return render_template('invite.html', form=form)
        password = generate_random58_id(12)
        secret = generate_otp_secret()
        counter = generate_random_int()
        info = {'id': userid,
                'email': email,
                'phone': phone,
                'user': user,
                'authentication': 'password',
                'mcf': preset_password(email, password),
                'otp': secret + ':' + str(counter),
                'created': 'invited: ' + datetime.utcnow().strftime('%Y-%m-%d')
               }
        USERS.put_item(info)
        action = 'invite'
        token = generate_timed_token(email, APP.config['SECRET_KEY'], action)
        code = generate_hotp_code(secret, counter)
        link = url_for('accept', email=email, token=token, action=action, _external=True)
        inviter = current_user.get_user()
        print(inviter)
        intro = u'{} has Invited you to join the Frosty Web community.'.format(inviter)
        send_email(email, 'Accept Invitation', 'invite',
                   user=user, intro=intro, link=link, password=password, code=code)
        flash('{} has been invited'.format(user))
        EVENT_MANAGER.web_event('invite', current_user.get_id(), **{"email": email})
        return redirect(url_for('profile'))
    return render_template('invite.html', form=form)

@APP.route("/forgot", methods=['GET', 'POST'])
def forgot():
    """ Request a password reset
    """
    errmsg = None
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    form = ForgotPasswordForm()

    # GET - populate form with email if passed
    if request.method == 'GET':
        form.email.data = get_parameter(request, 'email')

    # POST - validate form data
    elif form.validate_on_submit():
        agent = {"ip": get_ip_address(request), "from": get_user_agent(request)}
        email = form.email.data
        agent['email'] = email
        print('requesting password reset')
        userid = generate_user_id(CONFIG.get('user_id_hmac'), email)
        account = USERS.get_item('id', userid)
        if not account or 'error' in account:
            errmsg = 'Unable to validate your credentials'
        else:
            password = generate_random58_id(12)
            reset_mcf = preset_password(email, password)
            response = USERS.update_item('id', userid, 'reset_mcf', reset_mcf)
            if 'error' in response:
                errmsg = 'Request failed'
                EVENT_MANAGER.error_event('forgot', userid, response['error'], **agent)
            else:
                token = generate_timed_token(email, APP.config['SECRET_KEY'], 'reset')
                if account['authentication'] == 'password:sms':
                    fields = account['otp'].split(':')
                    secret = fields[0]
                    counter = int(fields[1]) + 1
                    code = generate_hotp_code(secret, counter)
                    response = USERS.update_item('id', userid, 'otp', secret + ':' + str(counter))
                    send_text(account['phone'], code + ' is your Frosty Web code')
                elif account['authentication'] == 'password:authy':
                    secret = account['otp']
                    code = generate_totp_code(secret)
                    send_text(account['phone'], code + ' is your Frosty Web code')

                link = url_for('reset', email=email, token=token, action='reset', _external=True)
                intro = 'You have requested a password reset.'
                send_email(email, 'Reset Password', 'reset',
                           user=account.get('user'), intro=intro, link=link, password=password)
                EVENT_MANAGER.web_event('forgot', userid, **agent)
                return redirect(url_for('reset', email=email, token=token, action='reset'))
    if errmsg:
        form.errors['Forgot'] = [errmsg]
        EVENT_MANAGER.error_event('forgot', userid, errmsg, **agent)
    return render_template('forgot.html', form=form)

@APP.route("/reset", methods=['GET', 'POST'])
def reset():
    """ Reset user password with emailed temporary password and token plus SMS/push token for 2FA
    """
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    errmsg = None
    form = ResetPasswordForm()
    # GET - populate form with required parameters (these are all hidden fields)
    if request.method == 'GET':
        email = get_parameter(request, 'email')
        token = get_parameter(request, 'token')
        action = get_parameter(request, 'action')
        if email is None or action is None or token is None:
            errmsg = 'Missing action, token or user name'
        form.email.data = email
        form.token.data = token
        form.action.data = action

    # POST - validate form data
    elif form.validate_on_submit():
        agent = {"ip": get_ip_address(request), "from": get_user_agent(request)}
        email = form.email.data
        token = form.token.data
        action = form.action.data
        userid = generate_user_id(CONFIG.get('user_id_hmac'), email)
        account = USERS.get_item('id', userid)
        if 'error' in account:
            form.errors['Reset'] = ['Unable to validate your credentials']
            EVENT_MANAGER.error_event('reset', userid, 'Unregistered email', **agent)
            #delay
            return render_template('reset.html', form=form)
        if 'reset_mcf' not in account:
            form.errors['Reset'] = ['Unable to validate your credentials']
            EVENT_MANAGER.error_event('reset', userid, 'No pending reset request', **agent)
            #delay
            return render_template('reset.html', form=form)
        session = SESSIONS.get_item('id', userid)
        if 'error' in session:
            session['id'] = userid
            session['email'] = email
            session['user'] = account.get('user')

        failures = check_account_lock(session)
        session['failures'] = failures
        if failures > MAX_FAILURES:
            errmsg = 'Your account is locked'
            form.errors['Reset'] = [errmsg]
            EVENT_MANAGER.error_event('reset', userid, errmsg, **agent)
            form.password.data = ''
            form.token.data = ''
            return render_template('reset.html', form=form)

        # Validate reset code, then password
        validated, value = validate_timed_token(token, APP.config['SECRET_KEY'], action)
        if validated and value == email:
            mcf = derive_key(form.password.data.encode('utf-8'), account.get('reset_mcf'))
            if mcf != account.get('reset_mcf'):
                errmsg = failed_account_attempt(session, failures)
                form.errors['Reset'] = [errmsg]
                EVENT_MANAGER.error_event('reset', userid, errmsg, **agent)
                form.password.data = ''
                form.token.data = ''
                #delay
                return render_template('reset.html', form=form)

            # Reset failed login counter if needed and clear locked
            session['failures'] = 0
            if 'locked_at' in session:
                del session['locked_at']
            EVENT_MANAGER.web_event('reset', userid, **agent)
            # Replace old password with temporary password and redirect to change password
            account['mcf'] = mcf
            del account['reset_mcf']
            USERS.put_item(account)

            print('validated user')
            agent['at'] = datetime.today().ctime()
            session['logins'] = agent
            if 'error' in session: # An error means no session entry exists
                del session['error']
            SESSIONS.put_item(session)
            username = account.get('user')
            user = User(email, username)
            user.is_authenticated = True
            user.is_active = True
            login_user(user, remember=form.remember.data)
            return redirect(url_for('change'))
        else:
            failmsg = 'The reset link is invalid or has expired'
            errmsg = failed_account_attempt(session, failures, failmsg)
            form.errors['Reset'] = [errmsg]
            EVENT_MANAGER.error_event('reset', userid, errmsg, **agent)
            form.password.data = ''
            form.token.data = ''
            #delay
            return redirect(url_for('resend', email=email, action=action))

    if errmsg:
        form.errors['Reset'] = [errmsg]
        EVENT_MANAGER.error_event('reset', userid, errmsg, **agent)
    return render_template('reset.html', form=form)

@APP.route("/register", methods=['GET', 'POST'])
def register():
    """ Register a new user account
    """
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    form = RegistrationForm()
    email = get_parameter(request, 'email')
    if email:
        form.email.data = email
    user = get_parameter(request, 'user')
    if user:
        form.user.data = user
    token = get_parameter(request, 'token')
    if token:
        form.token.data = token
    elif form.validate_on_submit():
        agent = {"ip": get_ip_address(request), "from": get_user_agent(request)}
        email = form.email.data
        phone = form.phone.data
        token = form.token.data
        user = form.user.data
        userid = generate_user_id(CONFIG.get('user_id_hmac'), email)
        account = USERS.get_item('id', userid)
        if 'error' not in account:
            errmsg = 'Email address already in use'
            form.errors['Register'] = [errmsg]
            EVENT_MANAGER.error_event('register', userid, errmsg, **agent)
            form.password.data = ''
            form.confirm.data = ''
            form.token.data = ''
            return render_template('register.html', form=form)
        validated, value = validate_timed_token(token, APP.config['SECRET_KEY'], 'register')
        if validated and value == email:
            print('registering new user')
        else:
            errmsg = 'Invalid or expired token'
            form.errors['Register'] = [errmsg]
            form.password.data = ''
            form.confirm.data = ''
            form.token.data = ''
            EVENT_MANAGER.error_event('register', userid, errmsg, **agent)
            return redirect(url_for('resend', email=email, action='register'))
        # Create json for new user
        secret = generate_otp_secret()
        counter = generate_random_int()
        info = {'id': generate_user_id(CONFIG.get('user_id_hmac'), email),
                'email': email,
                'phone': phone,
                'user': user,
                'authentication': 'password',
                'mcf': derive_key(form.password.data.encode('utf-8')),
                'otp': secret + ':' + str(counter),
                'created': 'pending: ' + datetime.utcnow().strftime('%Y-%m-%d')
               }
        user = User(email, user)
        user.is_authenticated = False
        user.is_active = False
        USERS.put_item(info)
        token = generate_timed_token(email, APP.config['SECRET_KEY'], 'confirm')
        code = generate_hotp_code(secret, counter)
        link = url_for('confirm', email=email, token=token, action='register', _external=True)
        intro = 'You have registered for a new account and need to confirm that it was really you.'
        send_email(email, 'Confirm Account', 'confirm',
                   user=user, intro=intro, link=link, code=code)
        flash('A confirmation email has been sent to ' + form.email.data)
        EVENT_MANAGER.web_event('register', userid, **agent)
    return render_template('register.html', form=form)

def handle_sigterm(signum, frame):
    """ Catch SIGTERM and SIGINT and stop the server by raising an exception
    """
    if frame:
        print(signum)
    raise SystemExit('Killed')

def main():
    """ Main for localhost testing via manage.py (start, stop, restart)
    """
    reason = 'Normal'
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('8.8.8.8', 1))  # Connecting to a Google UDP address
        host_ip = sock.getsockname()[0]
        sock.close()
        signal.signal(signal.SIGINT, handle_sigterm)
        signal.signal(signal.SIGTERM, handle_sigterm)

        print('Web server starting: %s:%d' % (host_ip, 8080))
        EVENT_MANAGER.log_event({'type': 'server.start', 'ip': host_ip})
        APP.run(debug=False, host='0.0.0.0', port=8080, threaded=True)
    except (KeyboardInterrupt, SystemExit):
        reason = 'Stopped'
    except (EnvironmentError, RuntimeError) as err:
        LOGGER.error(err)
        reason = str(err)
    except EndpointConnectionError as err:
        LOGGER.error(err)
        reason = str(err)
    EVENT_MANAGER.log_event({'type': 'server.stop', 'exit': reason})
    EVENT_MANAGER.flush_events()
    print(reason)

if __name__ == '__main__':
    LOGGER.setLevel(logging.ERROR)
    file_handler = logging.FileHandler("cyberfrosty.log")
    formatter = logging.Formatter('%(asctime)s %(levelname)s cyberfrosty:%(funcName)s %(message)s')
    file_handler.setFormatter(formatter)
    LOGGER.addHandler(file_handler)
    #print(USERS.load_table('users.json'))
    main()
