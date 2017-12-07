#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017 Alan Frost. All rights reserved.

Implementation of Web server using Flask framework

"""

import logging
import socket
from datetime import datetime
import time
from urlparse import urlparse, urljoin
import pytz

from botocore.exceptions import EndpointConnectionError
from flask import Flask, make_response, request, render_template, redirect, session, jsonify, abort, flash, url_for
from flask_mail import Mail, Message
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from decorators import async
from forms import (LoginForm, RegistrationForm, ConfirmForm, ChangePasswordForm, InviteForm,
                   PasswordResetRequestForm, PasswordResetForm, ResendConfirmForm)
from crypto import derive_key
from utils import (generate_timed_token, validate_timed_token, generate_user_id,
                   generate_random58_valid, preset_password, generate_random_int,
                   generate_otp_secret, generate_hotp_code)
from awsutils import load_config, DynamoDB, SNS
from recipe import RecipeManager
from vault import VaultManager

CONFIG = load_config('config.json')

USERS = DynamoDB(CONFIG, CONFIG.get('users'))
SESSIONS = DynamoDB(CONFIG, CONFIG.get('sessions'))
RECIPE_MANAGER = RecipeManager(CONFIG)
RECIPE_MANAGER.load_recipes('recipes.json')
VAULT_MANAGER = VaultManager(CONFIG)
SNS = SNS('FrostyWeb')

# Log exceptions and errors to /var/log/cyberfrosty.log
# 2017-05-11 08:29:26,696 ERROR webapp:main [Errno 51] Network is unreachable
LOGGER = logging.getLogger("CyberFrosty")


SERVER_VERSION = '0.1'
SERVER_START = int((datetime.now(tz=pytz.utc) -
                    datetime(1970, 1, 1, tzinfo=pytz.utc)).total_seconds())
MAX_FAILURES = 3
LOGIN_MANAGER = LoginManager()
application = Flask(__name__, static_url_path="")

application.config['SECRET_KEY'] = 'super secret key'
application.config['SSL_DISABLE'] = False
application.config['MAIL_SERVER'] = 'secure.emailsrvr.com'
application.config['MAIL_PORT'] = 465
application.config['MAIL_DEBUG'] = True
application.config['MAIL_USE_SSL'] = True
application.config['MAIL_USE_TLS'] = False
application.config['MAIL_USERNAME'] = 'alan@cyberfrosty.com'
application.config['MAIL_PASSWORD'] = ''
application.config['MAIL_SUBJECT_PREFIX'] = '[FROSTY]'
application.config['MAIL_SENDER'] = 'alan@cyberfrosty.com'
application.config['SESSION_COOKIE_HTTPONLY'] = True
application.config['REMEMBER_COOKIE_HTTPONLY'] = True

EMAIL_MANAGER = Mail(application)
LOGIN_MANAGER.init_app(application)
LOGIN_MANAGER.login_view = "login"
LOGIN_MANAGER.login_message = "Please login to access this page"
LOGIN_MANAGER.session_protection = "strong"

@async
def send_async_email(msg):
    """ Send an email from a new thread
    """
    with application.app_context():
        EMAIL_MANAGER.send(msg)

@async
def send_async_text(phone, msg):
    """ Send a text message from a new thread
    Args:
        number: phone number (e.g. '+17702233322')
        message: text
    """
    with application.app_context():
        SNS.send_sms(phone, msg)

class User(object):
    """ Class for the current user
    """
    def __init__(self, email, user=None, name=None, avatar=None):
        """ Constructor
        """
        self._email = email
        self._user = user or email
        self._userid = generate_user_id(CONFIG.get('user_id_hmac'), user)
        self._name = name
        self._avatar = avatar
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
        return generate_timed_token(self._user, application.config['SECRET_KEY'], action)

    def validate_token(self, token, action):
        """ Validate a timed token, tied to user name and action
        Args:
            token
            action: confirm, delete, register, reset, etc.
        Return:
            True or False
        """
        validated, value = validate_timed_token(token, application.config['SECRET_KEY'], action)
        if validated and value == self._user:
            return True
        return False

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return self._userid

    def get_username(self):
        return self._user

    def get_email(self):
        return self._email

    def get_name(self):
        return self._name

    def get_avatar(self):
        return self._avatar

@LOGIN_MANAGER.user_loader
def load_user(userid):
    """ Load user account details from database
    Args:
        username
    """
    mysession = SESSIONS.get_item('id', userid)
    if 'error' in mysession:
        account = USERS.get_item('id', userid)
        if 'error' not in account:
            print 'loaded user'
            user = User(account.get('email'), account.get('user'), account.get('name'), account.get('avatar'))
    elif 'failures' in mysession and mysession.get('failures') == 0:
        user = User(mysession.get('email'), mysession.get('user'), mysession.get('name'), mysession.get('avatar'))
        user.is_authenticated = True
        user.is_active = True
    return user

@LOGIN_MANAGER.unauthorized_handler
def unauthorized_page():
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

def send_email(recipients, subject, template, **kwargs):
    """ Send an email
    Args:
        list of recipients
        email subject line
        template
        arguments for templating
    """
    msg = Message(application.config['MAIL_SUBJECT_PREFIX'] + ' ' + subject,
                  sender=application.config['MAIL_SENDER'],
                  recipients=[recipients])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    send_async_email(msg)

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

def get_redirect_target():
    for target in get_parameter(request, 'next'), request.referrer:
        if not target:
            continue
        if is_safe_url(target):
            return target

def redirect_back(endpoint, **values):
    target = get_parameter(request, 'next')
    if not target or not is_safe_url(target):
        target = url_for(endpoint, **values)
    return redirect(target)

def next_is_valid(url):
    print url
    return True

@application.errorhandler(400)
def bad_request(error):
    """ Handle HTTP Bad Request error
    """
    if error.description:
        return make_response(jsonify({'error': str(error.description)}), 400)
    else:
        return make_response(jsonify({'error': str(error)}), 400)

@application.errorhandler(401)
def unauthorized(error):
    """ Handle HTTP Unauthorized error
    """
    if error.description:
        return make_response(jsonify({'error': str(error.description)}), 401)
    else:
        return make_response(jsonify({'error': str(error)}), 401)

@application.errorhandler(403)
def forbidden(error):
    """ Handle HTTP Forbidden error
    """
    if error.description:
        return make_response(jsonify({'error': str(error.description)}), 403)
    else:
        return make_response(jsonify({'error': str(error)}), 403)

@application.errorhandler(404)
def not_found(error):
    """ Handle HTTP Not Found error
    """
    if error.description:
        return make_response(jsonify({'error': str(error.description)}), 404)
    else:
        return make_response(jsonify({'error': str(error)}), 404)

@application.errorhandler(405)
def not_allowed(error):
    """ Handle HTTP Method Not Allowed error
    """
    if error.description:
        return make_response(jsonify({'error': str(error.description)}), 405)
    else:
        return make_response(jsonify({'error': str(error)}), 405)

@application.errorhandler(409)
def resource_exists(error):
    """ Handle HTTP Conflict error
    """
    if error.description:
        return make_response(jsonify({'error': str(error.description)}), 409)
    else:
        return make_response(jsonify({'error': str(error)}), 409)

@application.errorhandler(422)
def unprocessable_entity(error):
    """ Handle HTTP Unprocessable entity error
    """
    if error.description:
        return make_response(jsonify({'error': str(error.description)}), 422)
    else:
        return make_response(jsonify({'error': str(error)}), 422)

@application.errorhandler(500)
def server_error(error):
    """ Handle HTTP Server error
    """
    if 'description' in error:
        return make_response(jsonify({'error': str(error.description)}), 500)
    else:
        return make_response(jsonify({'error': str(error)}), 500)

@application.route('/google3dd7b0647e1f4d7a.html')
def google_site_verify():
    """ Google site verification
    """
    return render_template('google3dd7b0647e1f4d7a.html')

@application.route('/')
@application.route('/index')
def index():
    """ Show main landing page
    """
    return render_template('index.html')

@application.route('/api/server.info')
def server_info():
    """ Return server status information
    """
    url_fields = urlparse(request.url)
    timestamp = int((datetime.now(tz=pytz.utc) -
                     datetime(1970, 1, 1, tzinfo=pytz.utc)).total_seconds())
    uptime = timestamp - SERVER_START
    return jsonify({'server': url_fields.netloc, 'version': SERVER_VERSION, 'uptime': uptime})

@application.route('/recipes', methods=['GET'])
def recipes():
    """ Show recipes
    """
    recipe = request.args.get('recipe')
    if recipe is not None:
        html = RECIPE_MANAGER.get_rendered_recipe(recipe)
        return render_template('recipes.html', recipe=html, category=recipe)
    else:
        return render_template('recipes.html')

@application.route('/messages')
@login_required
def messages():
    """ Show messages
    """
    return render_template('messages.html')

@application.route('/vault')
@login_required
def vault():
    """ Show encrypted private content
    """
    account = USERS.get_item('id', generate_user_id(CONFIG.get('user_id_hmac'), current_user.get_username()))
    if not account or 'error' in account:
        return redirect(url_for('register', username=current_user.get_username()))
    myvault = account.get('vault')
    mcf = '<p hidden id="mcf">' + myvault.get('mcf', '') + '</p>'
    box = request.args.get('box')
    if box is not None:
        contents = '<p hidden id="safebox">' + myvault.get('contents', '') + '</p>'
        html = VAULT_MANAGER.get_rendered_box(myvault, box)
    else:
        html = VAULT_MANAGER.get_rendered_vault(myvault)
    return render_template('vault.html', contents=html, mcf=mcf)

@application.route('/privacy', methods=['GET'])
def privacy():
    """ Show privacy policy
    """
    return render_template('privacy.html')

@application.route("/confirm", methods=['GET', 'POST'])
def confirm():
    """ Confirm user account creation or action (delete) with emailed token
    """
    username = get_parameter(request, 'username')
    token = get_parameter(request, 'token')
    action = get_parameter(request, 'action')
    if username is None or token is None or action is None:
        abort(400, 'Missing user name, token or action')
    form = ConfirmForm()
    form.username.data = username
    form.token.data = token
    if form.validate_on_submit():
        userid = generate_user_id(CONFIG.get('user_id_hmac'), username)
        account = USERS.get_item('id', userid)
        if account is None:
            return redirect(url_for('register', username=username))
        session = SESSIONS.get_item('id', userid)
        if session is None:
            session = {}
            session['id'] = userid
        failures = session.get('failures', 0)
        validated, value = validate_timed_token(token, application.config['SECRET_KEY'], action)
        if validated and value == username:
            if action == 'register':
                # Update user account status
                if account['status'][:7] == 'pending':
                    account['status'] = 'confirmed: ' + time.mktime(datetime.utcnow().timetuple())
                    USERS.put_item(account)
                    session['failures'] = 0
                    SESSIONS.put_item(session)
                    flash('You have confirmed your account. Thanks!')
                return redirect(url_for('login', username=username))
        else:
            flash('The confirmation link is invalid or has expired.')
            if failures > MAX_FAILURES:
                return redirect(url_for('index'))
            session['failures'] = failures + 1
            SESSIONS.put_item(userid)
            return redirect(url_for('resend', username=username, action=action))

    return render_template('confirm.html', form=form)


@application.route("/login", methods=['GET', 'POST'])
def login():
    """ Login to user account with username/email and password
    """
    #if current_user and current_user.is_authenticated:
    #    print 'already logged in'
        #return redirect(url_for('index'))

    form = LoginForm()
    username = request.args.get('username')
    if username:
        form.username.data = username
    if form.validate_on_submit():
        # Login and validate the user.
        username = form.username.data
        userid = generate_user_id(CONFIG.get('user_id_hmac'), username)
        account = USERS.get_item('id', userid)
        if not account or 'error' in account:
            return redirect(url_for('register', username=username))
        mcf = derive_key(form.password.data.encode('utf-8'), account['mcf'])
        mysession = SESSIONS.get_item('id', userid)
        if 'error' in mysession:
            del mysession['error']
            mysession['id'] = userid
            mysession['user'] = username
            mysession['email'] = account.get('email')
            mysession['name'] = account.get('name')
            mysession['avatar'] = account.get('avatar')
            mysession['failures'] = 0
        failures = mysession.get('failures', 0)
        if mcf != account.get('mcf'):
            if failures > MAX_FAILURES:
                return redirect(url_for('index'))
            else:
                print 'Unable to validate your credentials'
                flash('Unable to validate your credentials')
                mysession['failures'] = failures + 1
                SESSIONS.put_item(mysession)
            return redirect(url_for('login', username=username))

        #EVENT_MANAGER.login_event(request, username)
        print 'validated user'
        # Reset failed login counter if needed
        if failures > 0:
            mysession['failures'] = 0
        mysession['login_at'] = int(time.mktime(datetime.utcnow().timetuple()))
        SESSIONS.put_item(mysession)
        user = User(account.get('email'), username, account.get('name'), account.get('avatar'))
        user.is_authenticated = True
        user.is_active = True
        login_user(user, remember=form.remember.data)

        return redirect_back('index')
    return render_template('login.html', form=form)

@application.route("/logout")
@login_required
def logout():
    """ Logout of user account
    """
    SESSIONS.delete_item('id', current_user.get_id())
    logout_user()
    return redirect(url_for('index'))

@application.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    """ Show user account profile
    """
    account = USERS.get_item('id', generate_user_id(CONFIG.get('user_id_hmac'), current_user.get_username()))
    if not account or 'error' in account:
        return redirect(url_for('register', username=current_user.get_username()))
    return render_template('profile.html', account=account)

@application.route("/headlines", methods=['GET', 'POST'])
@login_required
def headlines():
    """ Show headlines
    """
    account = USERS.get_item('id', generate_user_id(CONFIG.get('user_id_hmac'), current_user.get_username()))
    if not account or 'error' in account:
        return redirect(url_for('register', username=current_user.get_username()))
    return render_template('profile.html', account=account)

@application.route("/change", methods=['GET', 'POST'])
@login_required
def change():
    """ Change user account password
    """
    form = ChangePasswordForm()
    form.username.data = current_user.get_username()
    if form.validate_on_submit():
        print form.password.data
        print form.username.data
    return render_template('change.html', form=form)

@application.route("/resend", methods=['GET', 'POST'])
def resend():
    """ Regenerate and send a new confirmation code
    """
    username = request.args.get('username')
    action = request.args.get('action')
    if username is None or action is None:
        abort(400, 'Missing user name or action')
    form = ResendConfirmForm()
    form.username.data = username
    form.action.data = action
    if form.validate_on_submit():
        token = generate_timed_token(username, application.config['SECRET_KEY'], action)
        send_email(form.email.data, 'Confirm Your Account',
                   'email/confirm', username=form.username.data, token=token, action=action)
        flash('A confirmation email has been sent to ' + form.email.data)
        return redirect(url_for('login', username=form.username.data))
    return render_template('resend.html', form=form)

@application.route("/invite", methods=['GET', 'POST'])
@login_required
def invite():
    """ Invite a new user to join by providing an email address and phone number for them.
        An invitation is emailed to the user with a temporary password and a one time code
        is sent via text message to the phone number.
    """
    username = request.args.get('username')
    form = InviteForm()
    if form.validate_on_submit():
        username = form.email.data
        if USERS.get_item('id', generate_user_id(CONFIG.get('user_id_hmac'), username)):
            flash('Username ' + username + ' already taken')
            return redirect(url_for('invite', email=username, phone=form.phone.data))
        password = generate_random58_valid(10)
        info = {'id': generate_user_id(CONFIG.get('user_id_hmac'), username),
                'username': username,
                'email': username,
                'authentication': 'password',
                'mcf': preset_password(username, password),
                'status': 'invited: ' + time.mktime(datetime.utcnow().timetuple())
               }
        USERS.put_item(info)
        send_email(form.email.data, current_user.get_name() + ' has invited you to Frosty Web',
                   'email/confirm', username=username, password=password, action='invite')
        # send SMS
        secret = generate_otp_secret()
        counter = generate_random_int()
        code = generate_hotp_code(secret, counter)
        send_async_text(form.phone.data, code + ' is your Frosty Web code')
        return redirect(url_for('profile'))
    return render_template('invite.html', form=form)

@application.route("/forgot", methods=['GET', 'POST'])
def forgot():
    """ Request a password reset
    """
    username = request.args.get('username')
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        print 'requesting password reset'
        token = generate_timed_token(username, application.config['SECRET_KEY'], 'reset')
        send_email(form.email.data, 'Reset Your Password',
                   'email/confirm', username=form.username.data, token=token, action='reset')
        return redirect(url_for('reset', username=username))
    return render_template('forgot.html', form=form)

@application.route("/reset", methods=['GET', 'POST'])
def reset():
    """ Reset user password with emailed token
    """
    username = request.args.get('username')
    token = request.args.get('token')
    action = request.args.get('action')
    if username is None or token is None or action is None:
        abort(400, 'Missing user name, token or action')
    form = PasswordResetForm()
    if form.validate_on_submit():
        validated, value = validate_timed_token(token, application.config['SECRET_KEY'], action)
        if validated and value == username:
            print 'changing password'
            return redirect(url_for('login', form=form))
    return render_template('reset.html', form=form)

@application.route("/register", methods=['GET', 'POST'])
def register():
    """ Register a new user account
    """
    form = RegistrationForm(request.form)
    email = get_parameter(request, 'email')
    if email:
        form.email.data = email
    username = get_parameter(request, 'username')
    if username:
        form.username.data = username
    token = get_parameter(request, 'token')
    if token:
        form.token.data = token
    if request.method == 'POST' and form.validate_on_submit():
        if USERS.get_item('id', generate_user_id(CONFIG.get('user_id_hmac'), form.email.data)):
            flash('Username ' + form.email.data + ' already taken')
            return redirect(url_for('register', username=username, email=email))
        validated, value = validate_timed_token(token, application.config['SECRET_KEY'], 'register')
        if validated and value == email:
            print 'registering new user'
        else:
            flash('Invalid or expired token')
        # Create json for new user
        username = form.username.data or form.email.data
        info = {'id': generate_user_id(CONFIG.get('user_id_hmac'), username),
                'username': username,
                'email': form.email.data,
                'authentication': 'password',
                'mcf': derive_key(form.password.data),
                'status': 'pending: ' + time.mktime(datetime.utcnow().timetuple())
               }
        user = User(form.email.data, username)
        user.is_authenticated = False
        user.is_active = False
        USERS.put_item(info)
        token = generate_timed_token(username, application.config['SECRET_KEY'], 'register')
        send_email(form.email.data, 'Confirm Your Account',
                   'email/confirm', username=form.username.data, token=token, action='register')
        flash('A confirmation email has been sent to ' + form.email.data)
        return redirect(url_for('confirm', username=form.username.data))
    return render_template('register.html', form=form)

def main():
    reason = 'Normal'
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('8.8.8.8', 1))  # Connecting to a Google UDP address
        host_ip = sock.getsockname()[0]
        sock.close()
        print 'Web server starting: %s:%d' % (host_ip, 8080)
        application.run(debug=False, host='0.0.0.0', port=8080, threaded=True)
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
    print USERS.load_table('users.json')
    main()
