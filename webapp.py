#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017-2018 Alan Frost. All rights reserved.

Implementation of Web server using Flask framework

"""

import logging
import socket
from datetime import datetime
import time
from urlparse import urlparse, urljoin
import pytz
import simplejson as json
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
import jinja2

from botocore.exceptions import EndpointConnectionError
from flask import (Flask, make_response, request, render_template, redirect, jsonify,
                   abort, flash, url_for)
from flask_login import (LoginManager, current_user, login_required, login_user, logout_user,
                         fresh_login_required)
from decorators import async
from forms import (LoginForm, RegistrationForm, ConfirmForm, ChangePasswordForm, InviteForm,
                   VerifyForm, PasswordResetRequestForm, PasswordResetForm, ResendForm,
                   UploadForm)
from crypto import derive_key
from utils import (load_config, generate_timed_token, validate_timed_token, generate_user_id,
                   generate_random58_valid, preset_password, generate_random_int,
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
SES = SES('alan@cyberfrosty.com')

# Log exceptions and errors to /var/log/cyberfrosty.log
# 2017-05-11 08:29:26,696 ERROR webapp:main [Errno 51] Network is unreachable
LOGGER = logging.getLogger("CyberFrosty")


SERVER_VERSION = '0.1'
SERVER_START = int((datetime.now(tz=pytz.utc) -
                    datetime(1970, 1, 1, tzinfo=pytz.utc)).total_seconds())
MAX_FAILURES = 3
LOGIN_MANAGER = LoginManager()
APP = Flask(__name__, static_url_path="")

APP.config['SECRET_KEY'] = 'super secret key'
APP.config['SSL_DISABLE'] = False
APP.config['MAIL_SERVER'] = 'secure.emailsrvr.com'
APP.config['MAIL_PORT'] = 465
APP.config['MAIL_DEBUG'] = True
APP.config['MAIL_USE_SSL'] = True
APP.config['MAIL_USE_TLS'] = False
APP.config['MAIL_USERNAME'] = 'alan@cyberfrosty.com'
APP.config['MAIL_PASSWORD'] = ''
APP.config['MAIL_SUBJECT_PREFIX'] = '[FROSTY]'
APP.config['MAIL_SENDER'] = 'alan@cyberfrosty.com'
APP.config['SESSION_COOKIE_HTTPONLY'] = True
APP.config['REMEMBER_COOKIE_HTTPONLY'] = True
APP.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # Limit uploads to 16MB

LOGIN_MANAGER.init_app(APP)
LOGIN_MANAGER.login_view = "login"
LOGIN_MANAGER.login_message = "Please login to access this page"
LOGIN_MANAGER.session_protection = "strong"
CSRF = CSRFProtect(APP)

@async
def send_email(recipients, subject, action, **kwargs):
    """ Send an email from a new thread
    Args:
        list of recipients
        email subject line
        template
        arguments for templating
    """
    subject = APP.config['MAIL_SUBJECT_PREFIX'] + subject

    env = jinja2.Environment(loader=jinja2.FileSystemLoader('./templates'))
    template = env.get_template(action + '_email.txt')
    text = template.render(**kwargs)
    template = env.get_template(action + '_email.html')
    html = template.render(**kwargs)

    with APP.app_context():
        SES.send_email(recipients, subject, html, text)

@async
def send_text(phone, msg):
    """ Send a text message from a new thread
    Args:
        number: phone number (e.g. '+17702233322')
        message: text
    """
    #with APP.app_context():
    #    SNS.send_sms(phone, msg)
    print msg

class User(object):
    """ Class for the current user
    """
    def __init__(self, email, name=None):
        """ Constructor
        """
        print email, name
        self._email = email
        self._userid = generate_user_id(CONFIG.get('user_id_hmac'), email)
        self._name = name
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

    def get_name(self):
        return self._name

@LOGIN_MANAGER.user_loader
def load_user(userid):
    """ Load user account details from database
    Args:
        userid
    """
    print userid
    session = SESSIONS.get_item('id', userid)
    if 'error' in session:
        account = USERS.get_item('id', userid)
        if 'error' not in account:
            print 'loaded user'
            user = User(account.get('email'), account.get('name'))
    elif 'failures' in session and session.get('failures') == 0:
        user = User(session.get('email'), session.get('name'))
        user.is_authenticated = True
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
    uptime = timestamp - SERVER_START
    print get_user_agent(request)
    return jsonify({'server': url_fields.netloc, 'version': SERVER_VERSION, 'uptime': uptime})

@APP.route('/recipes', methods=['GET'])
def recipes():
    """ Show recipes
    """
    recipe = request.args.get('recipe')
    if recipe is not None:
        html = RECIPE_MANAGER.get_rendered_recipe(recipe)
        return render_template('recipes.html', search=RECIPE_LIST, recipe=html, title=recipe)
    else:
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
        print request.files['file']
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
        metadata = {'name': form.name.data,
                    'artform': form.artform.data,
                    'created': form.created.data,
                    'dimensions': form.dimensions.data,
                    'path': path,
                    'tags': tags}
        print json.dumps(metadata)
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

@APP.route("/confirm", methods=['GET', 'POST'])
def confirm():
    """ Confirm user account creation or action (delete) with emailed token
    """
    email = get_parameter(request, 'email')
    token = get_parameter(request, 'token')
    action = get_parameter(request, 'action')
    form = ConfirmForm()
    form.email.data = email
    form.token.data = token
    form.action.data = action
    if form.validate_on_submit():
        userid = generate_user_id(CONFIG.get('user_id_hmac'), email)
        account = USERS.get_item('id', userid)
        if account is None:
            #delay
            return redirect(url_for('register', email=email))
        session = SESSIONS.get_item('id', userid)
        if 'error' in session:
            session['id'] = userid
            session['email'] = email
            session['name'] = account.get('name')
            session['failures'] = 0
        failures = session.get('failures', 0)
        if failures > MAX_FAILURES and 'locked_at' in session:
            locktime = int(time.mktime(datetime.utcnow().timetuple())) - session['locked_at']
            if locktime < 1800:
                form.errors['Confirm'] = 'Your account is locked'
                #EVENT_MANAGER.error_event('confirm', userid, form.errors['Confirm'], **agent)
                return render_template('confirm.html', form=form)
            else:
                failures = 0  # Locked time has expired, reset failure counter
                session['failures'] = 0

        validated, value = validate_timed_token(token, APP.config['SECRET_KEY'], action)
        if validated and value == email:
            code = form.code.data
            if 'otp' in account:
                fields = account['otp'].split(':')
                secret = fields[0]
                counter = int(fields[1])
                counter = verify_hotp_code(secret, code, counter)
                if counter is None:
                    form.errors['Confirm'] = 'The confirmation code is invalid or has expired'
                    if 'error' in session: # An error means no session entry exists
                        del session['error']
                        session['failures'] = 1
                        SESSIONS.put_item(session)
                    else:
                        SESSIONS.update_item(userid, 'failures', failures + 1)
            if action == 'invite':
                # Update user account status
                if account['status'][:7] == 'invited':
                    status = 'confirmed: ' + str(time.mktime(datetime.utcnow().timetuple()))
                    response = USERS.update_item(userid, 'status', status)
                    flash('You have confirmed your account. Thanks!')
                return redirect(url_for('login', email=email))
            elif action == 'register':
                # Update user account status
                if account['status'][:7] == 'pending':
                    status = 'confirmed: ' + str(time.mktime(datetime.utcnow().timetuple()))
                    response = USERS.update_item(userid, 'status', status)
                    flash('You have confirmed your account. Thanks!')
                return redirect(url_for('login', email=email))
        else:
            session['failures'] = failures + 1
            if failures == MAX_FAILURES:
                form.errors['Confirm'] = 'Your account has been locked'
                session['locked_at'] = int(time.mktime(datetime.utcnow().timetuple()))
                SESSIONS.put_item(session)
            else:
                form.errors['Confirm'] = 'The confirmation link is invalid or has expired'
                if 'error' in session: # An error means no session entry exists
                    del session['error']
                    SESSIONS.put_item(session)
                else:
                    SESSIONS.update_item(userid, 'failures', failures + 1)

    return render_template('confirm.html', form=form)


@APP.route("/login", methods=['GET', 'POST'])
def login():
    """ Login to user account with email and password
    """
    form = LoginForm()
    email = request.args.get('email')
    if email:
        form.email.data = email
    if form.validate_on_submit():
        # Login and validate the user.
        agent = {"ip": get_ip_address(request), "from": get_user_agent(request)}
        email = form.email.data
        userid = generate_user_id(CONFIG.get('user_id_hmac'), email)
        account = USERS.get_item('id', userid)
        if not account or 'error' in account:
            form.errors['Login'] = 'Unable to validate your credentials'
            #EVENT_MANAGER.error_event('login', email, form.errors['Login'], **agent)
            return render_template('login.html', form=form)
        session = SESSIONS.get_item('id', userid)
        if 'error' in session:
            session['id'] = userid
            session['email'] = email
            session['name'] = account.get('name')
            session['failures'] = 0
        failures = session.get('failures', 0)
        if failures > MAX_FAILURES and 'locked_at' in session:
            locktime = int(time.mktime(datetime.utcnow().timetuple())) - session['locked_at']
            if locktime < 1800:
                form.errors['Login'] = 'Your account is locked'
                #EVENT_MANAGER.error_event('login', userid, form.errors['Login'], **agent)
                return render_template('login.html', form=form)
            else:
                failures = 0  # Locked time has expired, reset failure counter
                session['failures'] = 0

        # Check password
        mcf = derive_key(form.password.data.encode('utf-8'), account['mcf'])
        if mcf != account.get('mcf'):
            if 'error' in session: # An error means no session entry exists
                del session['error']
                session['failures'] = 1
                SESSIONS.put_item(session)
                form.errors['Login'] = 'Unable to validate your credentials'
            elif failures > MAX_FAILURES:
                session['locked_at'] = int(time.mktime(datetime.utcnow().timetuple()))
                session['failures'] = failures
                SESSIONS.put_item(session)
                form.errors['Login'] = 'Your account has been locked'
            else:
                SESSIONS.update_item(userid, 'failures', failures)
                form.errors['Login'] = 'Unable to validate your credentials'
            #EVENT_MANAGER.error_event('login', userid, form.errors['Login'], **agent)
            return render_template('login.html', form=form)

        # Reset failed login counter if needed and clear locked
        if failures > 0:
            session['failures'] = 0
            if 'locked_at' in session:
                del session['locked_at']
        #EVENT_MANAGER.status_event('login', userid, **agent)
        #logins = session['logins'] or []
        agent['at'] = datetime.today().ctime()
        #logins.append(agent)
        session['logins'] = agent
        if 'error' in session: # An error means no session entry exists
            del session['error']
        SESSIONS.put_item(session)
        user = User(email, account.get('name'))
        authentication = account['authentication']
        if authentication == 'password':
            user.is_authenticated = True
            user.is_active = True
            login_user(user, remember=form.remember.data)
            print 'validated user'
        elif authentication == 'password:totp':
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
    #EVENT_MANAGER.event('logout', userid, **agent)
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

    # Send a token to our user when they GET this page
    if request.method == 'GET':
        if authentication == 'password:authy':
            #send_authy_token_request(user.authy_id)
            print 'Sent code'
        elif authentication == 'password:totp':
            code = generate_totp_code(account['otp'])
            send_text(account['phone'], code + ' is your Frosty Web code')

    if form.validate_on_submit():
        token = form.token.data
        verified = False

        if authentication == 'password:authy':
            if token == '123456':
                verified = True
            #verified = verify_authy_token(user.authy_id, str(user_entered_code)).ok()
        elif authentication == 'password:totp':
            secret = account.get('otp')
            verified = verify_totp_code(secret, token)
            return redirect(url_for('profile'))

        if verified:
            target = request.args.get('next')
            if target is None or not is_safe_url(target):
                target = 'profile'
            return redirect(url_for(target))
        else:
            form.errors['Verify'] = 'Invalid or expired code'

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
@fresh_login_required
def change():
    """ Change user account password
    """
    form = ChangePasswordForm()
    email = request.args.get('email')
    form.email.data = email or current_user.get_email()
    if form.validate_on_submit():
        mcf = derive_key(form.password.data.encode('utf-8'))
        userid = generate_user_id(CONFIG.get('user_id_hmac'), form.email.data)
        response = USERS.update_item(userid, 'mcf', mcf)
        if 'error' in response:
            form.errors['Change'] = response['error']
        else:
            return redirect(url_for('profile'))
    return render_template('change.html', form=form)

@APP.route("/resend", methods=['GET', 'POST'])
def resend():
    """ Regenerate and send a new code
    """
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    email = request.args.get('email')
    action = request.args.get('action')
    if email is None or action is None:
        abort(400, 'Missing user name or action')
    form = ResendForm()
    form.email.data = email
    form.action.data = action
    if form.validate_on_submit():
        action = form.action.data
        token = generate_timed_token(email, APP.config['SECRET_KEY'], action)
        link = url_for(action, email=email, token=token, action=action, _external=True)
        if action == 'reset':
            send_email(form.email.data, 'Resending token', 'resend',
                       email=form.email.data, token=token, link=link)
            flash('A new confirmation code has been sent to ' + form.email.data)
            return redirect(url_for('confirm', email=form.email.data))
        #elif form.action.data == 'verify':
    return render_template('resend.html', form=form)

@APP.route("/invite", methods=['GET', 'POST'])
@fresh_login_required
def invite():
    """ Invite a new user to join by providing an email address and phone number for them.
        An invitation is emailed to the user with a temporary password and a one time code
        is sent via text message to the phone number.
    """
    form = InviteForm()
    if form.validate_on_submit():
        email = form.email.data
        userid = generate_user_id(CONFIG.get('user_id_hmac'), email)
        account = USERS.get_item('id', userid)
        if account and 'error' not in account:
            form.errors['Invite'] = 'Email address already in use'
            return render_template('invite.html', form=form)
        password = generate_random58_valid(12)
        secret = generate_otp_secret()
        counter = generate_random_int()
        info = {'id': userid,
                'email': email,
                'authentication': 'password',
                'mcf': preset_password(email, password),
                'otp': secret + ':' + str(counter),
                'status': 'invited: ' + str(time.mktime(datetime.utcnow().timetuple()))
               }
        USERS.put_item(info)
        action = 'invite'
        token = generate_timed_token(email, APP.config['SECRET_KEY'], action)
        link = url_for('confirm', email=email, token=token, action=action, _external=True)
        send_email(form.email.data, current_user.get_name() + ' has invited you to Frosty Web',
                   'invite', email=email, password=password, link=link,
                   inviter=current_user.get_name())
        # send SMS
        code = generate_hotp_code(secret, counter)
        send_text(form.phone.data, code + ' is your Frosty Web code')
        return redirect(url_for('profile'))
    return render_template('invite.html', form=form)

@APP.route("/forgot", methods=['GET', 'POST'])
def forgot():
    """ Request a password reset
    """
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    email = request.args.get('email')
    form = PasswordResetRequestForm()
    form.email.data = email
    if form.validate_on_submit():
        print 'requesting password reset'
        email = form.email.data
        userid = generate_user_id(CONFIG.get('user_id_hmac'), email)
        account = USERS.get_item('id', userid)
        if not account or 'error' in account:
            form.errors['Reset'] = 'Unable to validate your credentials'
        else:
            password = generate_random58_valid(12)
            account['reset_mcf'] = preset_password(email, password)
            token = generate_timed_token(email, APP.config['SECRET_KEY'], 'reset')
            if account['authentication'] == 'password:hotp':
                fields = account['otp'].split(':')
                secret = fields[0]
                counter = int(fields[1]) + 1
                code = generate_hotp_code(secret, counter)
                response = USERS.update_item(userid, 'otp', secret + ':' + str(counter))
                send_text(account['phone'], code + ' is your Frosty Web code')
            elif account['authentication'] == 'password:totp':
                secret = account['otp']
                code = generate_totp_code(secret)
                send_text(account['phone'], code + ' is your Frosty Web code')

            link = url_for('reset', email=email, token=token, action='reset', _external=True)
            send_email(email, 'Password reset request', 'reset',
                       email=email, password=password, link=link)
            return redirect(url_for('reset', email=email, action='reset'))
    return render_template('forgot.html', form=form)

@APP.route("/reset", methods=['GET', 'POST'])
def reset():
    """ Reset user password with emailed temporary password and token plus SMS/push token for 2FA
    """
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    email = request.args.get('email')
    action = request.args.get('action')
    if email is None or action is None:
        abort(400, 'Missing user name, token or action')
    form = PasswordResetForm()
    if form.validate_on_submit():
        # Login and validate the user.
        agent = {"ip": get_ip_address(request), "from": get_user_agent(request)}
        email = form.email.data
        userid = generate_user_id(CONFIG.get('user_id_hmac'), email)
        account = USERS.get_item('id', userid)
        if 'error' in account or 'reset_mcf' not in account:
            form.errors['Reset'] = 'Unable to validate your credentials'
            return render_template('reset.html', form=form)
        session = SESSIONS.get_item('id', userid)
        if 'error' in session:
            session['id'] = userid
            session['email'] = email
            session['name'] = account.get('name')
            session['failures'] = 0
        failures = session.get('failures', 0)
        if failures > MAX_FAILURES and 'locked_at' in session:
            locktime = int(time.mktime(datetime.utcnow().timetuple())) - session['locked_at']
            if locktime < 1800:
                form.errors['Reset'] = 'Your account is locked'
                #EVENT_MANAGER.error_event('reset', userid, form.errors['Reset'], **agent)
                return render_template('reset.html', form=form)
            else:
                failures = 0  # Locked time has expired, reset failure counter
                session['failures'] = 0

        # Validate reset code, then password
        token = form.token.data
        validated, value = validate_timed_token(token, APP.config['SECRET_KEY'], action)
        if validated and value == email:
            mcf = derive_key(form.password.data.encode('utf-8'), account.get('reset_mcf'))
            if mcf != account.get('reset_mcf'):
                if 'error' in session: # An error means no session entry exists
                    del session['error']
                    session['failures'] = 1
                    SESSIONS.put_item(session)
                    form.errors['Rest'] = 'Unable to validate your credentials'
                elif failures > MAX_FAILURES:
                    session['locked_at'] = int(time.mktime(datetime.utcnow().timetuple()))
                    session['failures'] = failures
                    SESSIONS.put_item(session)
                    form.errors['Reset'] = 'Your account has been locked'
                else:
                    SESSIONS.update_item(userid, 'failures', failures)
                    form.errors['Reset'] = 'Unable to validate your credentials'
                #EVENT_MANAGER.error_event('reset', userid, form.errors['Reset'], **agent)
                return render_template('reset.html', form=form)

            # Reset failed login counter if needed and clear locked
            session['failures'] = 0
            if 'locked_at' in session:
                del session['locked_at']
            #EVENT_MANAGER.status_event(request, email)
            # Replace old password with temporary password and redirect to change password
            account['mcf'] = mcf
            del account['reset_mcf']
            USERS.put_item(account)

            print 'validated user'
            agent['at'] = datetime.today().ctime()
            session['logins'] = agent
            if 'error' in session: # An error means no session entry exists
                del session['error']
            SESSIONS.put_item(session)
            user = User(email, account.get('name'))
            user.is_authenticated = True
            user.is_active = True
            login_user(user, remember=form.remember.data)
            return redirect(url_for('change'))
        else:
            SESSIONS.update_item(userid, 'failures', failures + 1)
            form.errors['Reset'] = 'Unable to validate your credentials'
    return render_template('reset.html', form=form)

@APP.route("/register", methods=['GET', 'POST'])
def register():
    """ Register a new user account
    """
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm(request.form)
    email = get_parameter(request, 'email')
    if email:
        form.email.data = email
    name = get_parameter(request, 'name')
    if name:
        form.name.data = name
    token = get_parameter(request, 'token')
    if token:
        form.token.data = token
    if request.method == 'POST' and form.validate_on_submit():
        email = form.email.data
        token = form.token.data
        userid = generate_user_id(CONFIG.get('user_id_hmac'), email)
        account = USERS.get_item('id', userid)
        if 'error' not in account:
            form.errors['Register'] = email + ' is already in use'
            return render_template('register.html', form=form)
        validated, value = validate_timed_token(token, APP.config['SECRET_KEY'], 'register')
        if validated and value == email:
            print 'registering new user'
        else:
            form.errors['Register'] = 'Invalid or expired token'
            return render_template('register.html', form=form)
        # Create json for new user
        info = {'id': generate_user_id(CONFIG.get('user_id_hmac'), email),
                'email': email,
                'authentication': 'password',
                'mcf': derive_key(form.password.data),
                'status': 'pending: ' + str(time.mktime(datetime.utcnow().timetuple()))
               }
        user = User(email, form.name.data)
        user.is_authenticated = False
        user.is_active = False
        USERS.put_item(info)
        token = generate_timed_token(email, APP.config['SECRET_KEY'], 'register')
        send_email(email, 'Confirm Your Account',
                   'register', email=email, token=token)
        flash('A confirmation email has been sent to ' + form.email.data)
        return redirect(url_for('confirm', email=email))
    return render_template('register.html', form=form)

def main():
    """ Main for localhost testing via manage.py (start, stop, restart)
    """
    reason = 'Normal'
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('8.8.8.8', 1))  # Connecting to a Google UDP address
        host_ip = sock.getsockname()[0]
        sock.close()
        print 'Web server starting: %s:%d' % (host_ip, 8080)
        APP.run(debug=False, host='0.0.0.0', port=8080, threaded=True)
    except (KeyboardInterrupt, SystemExit):
        reason = 'Stopped'
    except (EnvironmentError, RuntimeError) as err:
        LOGGER.error(err)
        reason = str(err)
    except EndpointConnectionError as err:
        LOGGER.error(err)
        reason = str(err)
    print reason

if __name__ == '__main__':
    LOGGER.setLevel(logging.ERROR)
    file_handler = logging.FileHandler("cyberfrosty.log")
    formatter = logging.Formatter('%(asctime)s %(levelname)s cyberfrosty:%(funcName)s %(message)s')
    file_handler.setFormatter(formatter)
    LOGGER.addHandler(file_handler)
    #print USERS.load_table('users.json')
    main()
