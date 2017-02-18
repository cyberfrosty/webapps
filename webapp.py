#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017 Alan Frost, All rights reserved.

Implementation of Web server

"""

import socket

from flask import Flask, request, render_template, redirect, jsonify, abort, flash, url_for
from flask_mail import Mail, Message
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from decorators import async
from forms import (LoginForm, RegistrationForm, ConfirmForm, ChangePasswordForm,
                   PasswordResetRequestForm, PasswordResetForm, ResendConfirmForm)
from crypto import derive_key
from utils import generate_timed_token, validate_timed_token
from awsutils import DynamoDB
USERS = DynamoDB('Users')
USERS.create_table('Users', 'username')

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
application.config['MAIL_SUBJECT_PREFIX'] = '[IONU]'
application.config['MAIL_SENDER'] = 'alan@ionu.com'

mail = Mail(application)
login_manager.init_app(application)
login_manager.login_view = "login"
login_manager.login_message = "Please login to access this page"
login_manager.session_protection = "strong"


@login_manager.user_loader
def load_user(username):
    return USERS.get_item('username', username)

@async
def send_async_email(msg):
    with application.app_context():
        mail.send(msg)

class User(object):
    def __init__(self, username):
        self.username = username
        self.name = None
        self.email = None
        self.public_key = None
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
        return generate_timed_token(self.username, application.config['SECRET_KEY'], action)

    def validate_token(self, token, action):
        validated, value = validate_timed_token(token, application.config['SECRET_KEY'], action)
        if validated and value == self.username:
            return True
        return False

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return self.username

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
    return render_template('index.html')

@application.route('/IONUBusiness')
def IONUBusiness():
    return render_template('IONUBusiness.html')

@application.route('/IOT')
def IOT():
    return render_template('IOT.html')

@application.route('/About')
def About():
    return render_template('About.html')

@application.route('/Privacy')
def Privacy():
    return render_template('Privacy.html')

@application.route("/confirm", methods=['GET', 'POST'])
def confirm():
    username = request.args.get('username')
    token = request.args.get('token')
    action = request.args.get('action')
    if username is None or token is None or action is None:
        abort(400)
    form = ConfirmForm()
    form.username.data = username
    form.token.data = token
    if form.validate_on_submit():
        user = load_user(username)
        if user.authenticated:
            return redirect(url_for('index'))
        elif user.confirmed:
            return redirect(url_for('login', username=username))
        elif user.validate_token(token, action):
            if action == 'register':
                # Update cached user map and identity database
                #USERS[username].confirmed = True
                flash('You have confirmed your account. Thanks!')
                return redirect(url_for('login', username=username))
        else:
            flash('The confirmation link is invalid or has expired.')
            return redirect(url_for('index'))

    return render_template('confirm.html', form=form)


@application.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    username = request.args.get('username')
    if username:
        form.username.data = username
    if form.validate_on_submit():
        # Login and validate the user.
        username = form.username.data
        account = USERS.get_item('username', username)
        if not account or 'error' in account:
            return redirect(url_for('register', username=username))
        mcf = derive_key(form.password.data, account['mcf'])
        if mcf != account['mcf']:
            flash('Unable to validate your credentials.')
            return redirect(url_for('login', username=username))

        print 'validated user'
        user = User(username)
        user.is_authenticated = True
        user.is_confirmed = True
        user.email = account.get('email')
        user.name = account.get('descrption')
        user.public_key = account.get('public_key')
        #USERS[username] = user
        if login_user(user, remember=form.remember.data):
            flash('Logged in successfully.')
        print 'login user'

        return redirect(url_for('profile', username=username, name=account.get('name')))
    return render_template('login.html', form=form)

@application.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@application.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    print current_user
    return render_template('profile.html', user=current_user)

@application.route("/change", methods=['GET', 'POST'])
def change():
    form = ChangePasswordForm()
    return render_template('change.html', form=form)

@application.route("/resend", methods=['GET', 'POST'])
def resend():
    form = ResendConfirmForm()
    return render_template('resend.html', form=form)

@application.route("/forgot", methods=['GET', 'POST'])
def forgot():
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
    form = RegistrationForm(request.form)
    username = request.args.get('username')
    if username:
        form.username.data = username
    if request.method == 'POST': # and form.validate_on_submit():
        # Create json for identity_create call,
        info = {'username': form.username.data,
                'email': form.email.data,
                'password': form.password.data,
                'account_status': 'pending'}
        user = User(form.username.data)
        #db_session.add(user)
        token = generate_timed_token(username, application.config['SECRET_KEY'], 'register')
        send_email(form.email.data, 'Confirm Your Account',
                   'email/confirm', username=form.username.data, token=token, action='register')
        flash('A confirmation email has been sent to ' + form.email.data)
        return redirect(url_for('login', username=form.username.data))
    print 'validate failed', form.username.data, form.email.data, form.password.data, form.confirm.data
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
        rc = 1
    print reason

if __name__ == '__main__':
    main()
