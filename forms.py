#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017 Alan Frost, All rights reserved.

Implementation of user forms

"""
import re
from flask_wtf import FlaskForm
from wtforms import BooleanField, StringField, PasswordField, SubmitField
from wtforms import ValidationError, validators
from wtforms.fields.html5 import EmailField

class UserNameValidator(object):
    def __init__(self, message=None):
        if not message:
            message = u'* Invalid'
        self.message = message

    def __call__(self, form, field):
        if re.match(r"[^@]+@[^@]+\.[^@]+", field.data) or re.match(r"^[A-Za-z][A-Za-z0-9\._-]*$", field.data):
            pass
        else:
            raise ValidationError(self.message)

class LoginForm(FlaskForm):
    """ Login
    """
    username = StringField('Username or Email', validators=[
        validators.InputRequired(message="* Required"),
        validators.Length(4, 48)])
    password = PasswordField('Password', validators=[
        validators.InputRequired(message="* Required"),
        validators.Length(8, 48)])
    remember = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

class ConfirmForm(FlaskForm):
    """ Confirm account with token
    """
    username = StringField('Username', [validators.Length(4, 64)])
    token = StringField('Token', [validators.InputRequired(message="* Required")])
    submit = SubmitField('Confirm Account')

class ResendConfirmForm(FlaskForm):
    """ Resend a new confirm account token
    """
    email = EmailField('Email Address', [
        validators.InputRequired(message="* Required"),
        validators.Email(message="* Invalid")
    ])
    submit = SubmitField('Resend Account Confirmation')

class RegistrationForm(FlaskForm):
    """ Register a new account
    """
    username = StringField('Username', [
        validators.InputRequired(message="* Required"),
        validators.Length(4, 64, message="* Length (4, 64)"),
        UserNameValidator()
    ])
    email = EmailField('Email Address', [
        validators.InputRequired(message="* Required"),
        validators.Email(message="* Invalid")])
    password = PasswordField('New Password', [
        validators.InputRequired(message="* Required"),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Verify password', [validators.InputRequired(message="* Required")])
    accept_tos = BooleanField('I accept the TOS', [validators.InputRequired()])

class ChangePasswordForm(FlaskForm):
    """ Change password
    """
    password = PasswordField('New password', [
        validators.InputRequired(message="* Required"),
        validators.EqualTo('confirm', message='* Passwords must match')
    ])
    confirm = PasswordField('Verify password', [validators.InputRequired(message="* Required")])
    submit = SubmitField('Change Password')

class PasswordResetRequestForm(FlaskForm):
    """ Request a password reset
    """
    email = EmailField('Email Address', [
        validators.InputRequired(message="* Required"),
        validators.Email(message="* Invalid")
    ])
    submit = SubmitField('Request Password Reset')

class PasswordResetForm(FlaskForm):
    """ Reset a password with token
    """
    token = StringField('Token', [validators.InputRequired(message="* Required")])
    password = PasswordField('New Password', validators=[
        validators.InputRequired(message="* Required"),
        validators.EqualTo('confirm', message='* Passwords must match')
    ])
    confirm = PasswordField('Confirm password', [validators.InputRequired(message="* Required")])
    submit = SubmitField('Reset Password')
