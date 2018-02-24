#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017-2018 Alan Frost, All rights reserved.

Implementation of user forms

"""
from flask_wtf import FlaskForm
from wtforms import (BooleanField, HiddenField, PasswordField, StringField, SubmitField,
                     FileField, ValidationError)
from wtforms.validators import Length, InputRequired, Email, EqualTo, Regexp

from utils import check_name, check_password, check_username, check_phone

#import phonenumbers
#https://github.com/daviddrysdale/python-phonenumbers

class UserNameValidator(object):
    """ User name validator, unicode except for control, punctuation, separator or symbols
    """
    def __init__(self, message=None):
        if not message:
            message = u'Invalid user name'
        self.message = message

    def __call__(self, form, field):
        length = field.data and len(field.data) or 0
        if length == 0:
            pass
        elif check_username(field.data):
            pass
        else:
            raise ValidationError(self.message)

class NameValidator(object):
    """ Display name validator, unicode except for control, symbols and non-space separator
    """
    def __init__(self, message=None):
        if not message:
            message = u'Invalid user name'
        self.message = message

    def __call__(self, form, field):
        length = field.data and len(field.data) or 0
        if length == 0:
            pass
        elif check_name(field.data):
            pass
        else:
            raise ValidationError(self.message)

class PasswordValidator(object):
    """ Simple password validator for at least 8 characters with a lower, upper and digit
    """
    def __init__(self, message=None):
        if not message:
            message = u'Password must be at least 8 characters, with UPPER/lowercase and numbers'
        self.message = message

    def __call__(self, form, field):
        length = field.data and len(field.data) or 0
        if length == 0:
            pass
        elif check_password(field.data):
            pass
        else:
            raise ValidationError(self.message)

class PhoneNumberValidator(object):
    """ Phone number validator
    """
    def __init__(self, message=None):
        if not message:
            message = u'* Invalid phone number'
        self.message = message

    def __call__(self, form, field):
        length = field.data and len(field.data) or 0
        if length == 0:
            pass
        elif check_phone(field.data):
            pass
        else:
            raise ValidationError(self.message)
        #else:
        #    try:
        #        input_number = phonenumbers.parse(field.data)
        #        if not (phonenumbers.is_valid_number(input_number)):
        #            raise ValidationError(self.message)
        #    except:
        #        input_number = phonenumbers.parse("+1"+field.data)
        #        if not (phonenumbers.is_valid_number(input_number)):
        #            raise ValidationError(self.message)

class LoginForm(FlaskForm):
    """ Login
    """
    email = StringField('Email', validators=[
        InputRequired(),
        Email()])
    password = PasswordField('Password', validators=[
        InputRequired(),
        Length(8, 64)])
    remember = BooleanField('Keep me logged in')
    submit = SubmitField('Login')

class InviteForm(FlaskForm):
    """ Invite a new user
    """
    email = StringField('Email', validators=[
        InputRequired(),
        Email()])
    phone = StringField('Phone', validators=[
        PhoneNumberValidator()])
    user = StringField('Name', validators=[InputRequired(), NameValidator()])
    submit = SubmitField('Invite')

class AcceptForm(FlaskForm):
    """ Accept invitation with link token, temporary password and code
    """
    action = HiddenField('Action')
    email = HiddenField('Email')
    token = HiddenField('Token')
    user = StringField('Name', validators=[InputRequired(), NameValidator()])
    phone = StringField('Phone', validators=[PhoneNumberValidator()])
    oldpassword = PasswordField('Password', validators=[
        InputRequired(),
        PasswordValidator()])
    password = PasswordField('New Password', validators=[
        InputRequired(),
        EqualTo('confirm', message='Passwords must match')
    ])
    code = StringField('Code', validators=[InputRequired(), Regexp(r'^(\d{6,8})$')])
    confirm = PasswordField('Confirm password', validators=[InputRequired()])
    submit = SubmitField('Accept Invitation')

class ConfirmForm(FlaskForm):
    """ Confirm account with token
    """
    action = HiddenField('Action')
    email = HiddenField('Email')
    token = HiddenField('Token')
    code = StringField('Code', validators=[InputRequired(), Regexp(r'^(\d{6,8})$')])
    submit = SubmitField('Confirm Account')

class VerifyForm(FlaskForm):
    """ Verify 2FA code
    """
    action = HiddenField('Action')
    email = HiddenField('Email')
    phone = HiddenField('Phone')
    code = StringField('Code', validators=[InputRequired(), Regexp(r'^(\d{6,8})$')])
    submit = SubmitField('Verify Code')

class UploadForm(FlaskForm):
    """ Upload an artistic work
    """
    file = FileField('Filename')
    title = StringField('Title', validators=[Length(2, 128)])
    artform = StringField('Artform', validators=[Length(0, 128)])
    created = StringField('Date', validators=[Length(6, 32)])
    dimensions = StringField('Dimensions', validators=[Length(0, 64)])
    tags = StringField('Tags', validators=[Length(0, 128)])
    submit = SubmitField('Upload Image')

class ResendForm(FlaskForm):
    """ Resend a confirmtion or verification token
    """
    action = HiddenField('Action')
    email = StringField('Email Address', validators=[
        InputRequired(),
        Email()])
    phone = StringField('phone', validators=[PhoneNumberValidator()])
    submit = SubmitField('Get New Code')

class RegistrationForm(FlaskForm):
    """ Register a new account
    """
    user = StringField('Name', validators=[InputRequired(), NameValidator()])
    email = StringField('Email Address', validators=[
        InputRequired(),
        Email()])
    phone = StringField('Phone', validators=[PhoneNumberValidator()])
    password = PasswordField('New password', validators=[
        InputRequired(),
        PasswordValidator(),
        EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Confirm password', validators=[InputRequired()])
    token = StringField('Token', validators=[InputRequired()])

class ChangePasswordForm(FlaskForm):
    """ Change password
    """
    email = HiddenField('Email')
    oldpassword = PasswordField('Password', validators=[
        InputRequired(),
        Length(8, 64)])
    password = PasswordField('New Password', validators=[
        InputRequired(),
        PasswordValidator(),
        EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Confirm password', validators=[InputRequired()])
    submit = SubmitField('Change Password')

class ForgotPasswordForm(FlaskForm):
    """ Request a password reset
    """
    email = StringField('Email Address', validators=[
        InputRequired(),
        Email()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    """ Reset a password with link token, temporary password and code
    """
    email = HiddenField('Email')
    action = HiddenField('Action')
    token = HiddenField('Token')
    oldpassword = PasswordField('Password', validators=[
        InputRequired(),
        Length(8, 64)])
    password = PasswordField('New Password', validators=[
        InputRequired(),
        PasswordValidator(),
        EqualTo('confirm', message='Passwords must match')
    ])
    code = StringField('Code', validators=[InputRequired(), Regexp(r'^(\d{6,8})$')])
    confirm = PasswordField('Confirm password', validators=[InputRequired()])
    submit = SubmitField('Reset Password')
