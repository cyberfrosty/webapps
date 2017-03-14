#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017 Alan Frost, All rights reserved.

Implementation of Web server

"""

import socket
from datetime import datetime
import time

from flask import Flask, request, render_template, redirect, jsonify, abort, flash, url_for
from flask_mail import Mail, Message
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from decorators import async
from forms import (LoginForm, RegistrationForm, ConfirmForm, ChangePasswordForm,
                   PasswordResetRequestForm, PasswordResetForm, ResendConfirmForm)
from crypto import derive_key
from utils import generate_timed_token, validate_timed_token, generate_user_id
from awsutils import DynamoDB
USERS = DynamoDB('Users')
#USERS.create_table('Users', 'id')
SESSIONS = DynamoDB('Sessions')
#SESSIONS.create_table('Sessions', 'id')

MAX_FAILURES = 3
login_manager = LoginManager()
application = Flask(__name__, static_url_path="")

application.config['SECRET_KEY'] = 'secret'
application.config['SSL_DISABLE'] = False
#application.config['MAIL_SERVER'] = 'mex06.emailsrvr.com'
application.config['MAIL_SERVER'] = 'secure.emailsrvr.com'
application.config['MAIL_PORT'] = 465 #587
application.config['MAIL_DEBUG'] = True
application.config['MAIL_USE_SSL'] = True
application.config['MAIL_USE_TLS'] = False
application.config['MAIL_USERNAME'] = 'alan@ionu.com'
application.config['MAIL_PASSWORD'] = ''
application.config['MAIL_SUBJECT_PREFIX'] = '[FROSTY]'
application.config['MAIL_SENDER'] = 'alan@ionu.com'

mail = Mail(application)
login_manager.init_app(application)
login_manager.login_view = "login"
login_manager.login_message = "Please login to access this page"
login_manager.session_protection = "strong"


@async
def send_async_email(msg):
    """ Send an email from a new thread
    """
    with application.app_context():
        mail.send(msg)

class User(object):
    """ Class for the current user
    """
    def __init__(self, email, username=None, name=None, avatar=None):
        """ Constructor
        """
        self._email = email
        self._username = username or email
        self._userid = generate_user_id(username)
        self._name = name
        self._avatar = avatar
        self._authenticated = False
        self._confirmed = False

    @property
    def is_authenticated(self):
        return self._authenticated

    @is_authenticated.setter
    def is_authenticated(self, value):
        self._authenticated = value

    @property
    def is_confirmed(self):
        return self._confirmed

    @is_confirmed.setter
    def is_confirmed(self, value):
        self._confirmed = value

    def generate_token(self, action):
        """ Generate timed token, tied to username and action
        Args:
            action: confirm, reset, delete, etc.
        Return:
            URL safe encoded token
        """
        return generate_timed_token(self._username, application.config['SECRET_KEY'], action)

    def validate_token(self, token, action):
        validated, value = validate_timed_token(token, application.config['SECRET_KEY'], action)
        if validated and value == self._username:
            return True
        return False

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return self._userid

@login_manager.user_loader
def load_user(username):
    account = USERS.get_item('username', generate_user_id(username))
    user = User(account.get('email'), username, account.get('name'), account.get('avatar'))
    return user

def send_email(recipients, subject, template, **kwargs):
    msg = Message(application.config['MAIL_SUBJECT_PREFIX'] + ' ' + subject,
                  sender=application.config['MAIL_SENDER'],
                  recipients=[recipients])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    send_async_email(msg)

def next_is_valid(url):
    print url
    return True

@application.route('/')
def index():
    """ Show main landing page
    """
    return render_template('index.html')

@application.route('/recipes')
def recipes():
    """ Show recipes
    """
    return render_template('recipes.html')

@application.route('/privacy')
def privacy():
    """ Show privacy policy
    """
    return render_template('privacy.html')

@application.route("/confirm", methods=['GET', 'POST'])
def confirm():
    """ Confirm user account creation or action (delete) with emailed token
    """
    username = request.args.get('username')
    token = request.args.get('token')
    action = request.args.get('action')
    if username is None or token is None or action is None:
        abort(400)
    form = ConfirmForm()
    form.username.data = username
    form.token.data = token
    if form.validate_on_submit():
        userid = generate_user_id(username)
        account = USERS.get_item('username', userid)
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
                    USERS.put_item('id', account)
                    session['failures'] = 0
                    SESSIONS.put_item('id', session)
                    flash('You have confirmed your account. Thanks!')
                return redirect(url_for('login', username=username))
        else:
            flash('The confirmation link is invalid or has expired.')
            if failures > MAX_FAILURES:
                return redirect(url_for('index'))
            session['failures'] = failures + 1
            SESSIONS.put_item('id', userid)
            return redirect(url_for('resend', username=username, action=action))

    return render_template('confirm.html', form=form)


@application.route("/login", methods=['GET', 'POST'])
def login():
    """ Login to user account with username/email and password
    """
    form = LoginForm()
    username = request.args.get('username')
    if username:
        form.username.data = username
    if form.validate_on_submit():
        # Login and validate the user.
        username = form.username.data
        userid = generate_user_id(username)
        account = USERS.get_item('id', userid)
        if not account or 'error' in account:
            return redirect(url_for('register', username=username))
        mcf = derive_key(form.password.data, account['mcf'])
        session = SESSIONS.get_item('id', userid)
        if session is None:
            session = {}
            session['id'] = userid
        failures = session.get('failures', 0)
        if mcf != account.get('mcf'):
            if failures > MAX_FAILURES:
                return redirect(url_for('index'))
            else:
                flash('Unable to validate your credentials.')
                session['failures'] = failures + 1
                SESSIONS.put_item('id', session)
            return redirect(url_for('login', username=username))

        print 'validated user'
        # Reset failed login counter if needed
        if failures > 0:
            session['failures'] = 0
        session['login_at'] = int(time.mktime(datetime.utcnow().timetuple()))
        SESSIONS.put_item('id', session)
        user = User(account.get('email'), username, account.get('name'), account.get('avatar'))
        user.is_authenticated = True
        user.is_confirmed = True
        if login_user(user, remember=form.remember.data):
            flash('Logged in successfully.')

        return redirect(url_for('profile', username=username, name=account.get('name')))
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
    return render_template('profile.html', user=current_user)

@application.route("/change", methods=['GET', 'POST'])
@login_required
def change():
    """ Change user account password
    """
    form = ChangePasswordForm()
    return render_template('change.html', form=form)

@application.route("/resend", methods=['GET', 'POST'])
def resend():
    """ Regenerate and send an account confirmation code
    """
    username = request.args.get('username')
    action = request.args.get('action')
    if username is None or action is None:
        abort(400)
    form = ResendConfirmForm()
    form.username.data = username
    form.action.data = action
    if form.validate_on_submit():
        token = generate_timed_token(username, application.config['SECRET_KEY'], 'register')
        send_email(form.email.data, 'Confirm Your Account',
                   'email/confirm', username=form.username.data, token=token, action='register')
        flash('A confirmation email has been sent to ' + form.email.data)
        return redirect(url_for('login', username=form.username.data))
    return render_template('resend.html', form=form)

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
        abort(400)
    form = PasswordResetForm()
    if form.validate_on_submit():
        print 'changing password'
        return redirect(url_for('login', form=form))
    return render_template('reset.html', form=form)

@application.route("/register", methods=['GET', 'POST'])
def register():
    """ Register for a new user account
    """
    form = RegistrationForm(request.form)
    email = request.args.get('email')
    if email:
        form.email.data = email
    username = request.args.get('username')
    if username:
        form.username.data = username
    if request.method == 'POST' and form.validate_on_submit():
        if USERS.get_item('username', generate_user_id(form.email.data)):
            flash('Username ' + form.email.data + ' already taken')
            return redirect(url_for('register', username=username, email=email))
        # Create json for new user
        info = {'id': generate_user_id(form.username.data),
                'authentication': 'password',
                'mcf': derive_key(form.password.data),
                'status': 'pending: ' + time.mktime(datetime.utcnow().timetuple()),
                'pii': {
                    'username': form.username.data,
                    'email': form.email.data
                }
               }
        user = User(form.email.data, form.username.data)
        user.is_authenticated = False
        user.is_confirmed = False
        USERS.put_item('id', info)
        token = generate_timed_token(username, application.config['SECRET_KEY'], 'register')
        send_email(form.email.data, 'Confirm Your Account',
                   'email/confirm', username=form.username.data, token=token, action='register')
        flash('A confirmation email has been sent to ' + form.email.data)
        return redirect(url_for('login', username=form.username.data))
    return render_template('register.html', form=form)

def main():
    reason = 'Normal'
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('8.8.8.8', 1))  # Connecting to a Google UDP address
        host_ip = sock.getsockname()[0]
        sock.close()
        print 'Web server starting: %s:%d' % (host_ip, 8080)
        application.run(debug=True, host='0.0.0.0', port=8080, threaded=True)
    except (KeyboardInterrupt, SystemExit):
        reason = 'Stopped'
    except (EnvironmentError, RuntimeError) as err:
        reason = err
    print reason

if __name__ == '__main__':
    main()
