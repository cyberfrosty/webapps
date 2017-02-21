#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017 Alan Frost, All rights reserved.

Implementation of user forms

"""
from flask_wtf import FlaskForm
from wtforms import BooleanField, StringField, PasswordField, SubmitField, validators
from wtforms.validators import Required, Length, Email, Regexp, EqualTo

class LoginForm(FlaskForm):
    """ Login
    """
    username = StringField('Username or Email', validators=[Required(), Length(4, 48)])
    password = PasswordField('Password', validators=[Required(), Length(8, 48)])
    remember = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

class ConfirmForm(FlaskForm):
    """ Confirm account with token
    """
    username = StringField('Username', [validators.Length(4, 64)])
    token = StringField('Token', validators=[Required()])
    submit = SubmitField('Confirm Account')

class ResendConfirmForm(FlaskForm):
    """ Resend a new confirm account token
    """
    email = StringField('Email Address', validators=[Required(), Length(2, 48), Email()])
    submit = SubmitField('Resend Account Confirmation')

class RegistrationForm(FlaskForm):
    """ Register a new account
    """
    username = StringField('Username', validators=[
        Length(4, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                              'Usernames must have only letters, '
                              'numbers, dots or underscores')])
    email = StringField('Email Address', validators=[Required(), Length(2, 48), Email()])
    password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Verify password', validators=[Required()])
    accept_tos = BooleanField('I accept the TOS', [validators.DataRequired()])

class ChangePasswordForm(FlaskForm):
    """ Change password
    """
    password = PasswordField('New password', validators=[
        Required(), EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Verify password', validators=[Required()])
    submit = SubmitField('Change Password')

class PasswordResetRequestForm(FlaskForm):
    """ Request a password reset
    """
    email = StringField('Email Address', validators=[Required(), Length(4, 64), Email()])
    submit = SubmitField('Request Password Reset')

class PasswordResetForm(FlaskForm):
    """ Reset a password with token
    """
    token = StringField('Token', validators=[Required()])
    password = PasswordField('New Password', validators=[
        Required(), EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Confirm password', validators=[Required()])
    submit = SubmitField('Reset Password')
