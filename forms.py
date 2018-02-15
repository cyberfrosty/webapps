#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017-2018 Alan Frost, All rights reserved.

Implementation of user forms

"""
import re
from flask_wtf import FlaskForm
from wtforms import BooleanField, HiddenField, PasswordField, StringField, SubmitField, FileField
from wtforms import ValidationError
from wtforms.validators import Length, InputRequired, Email, EqualTo

#import phonenumbers
#https://github.com/daviddrysdale/python-phonenumbers

class UserNameValidator(object):
    """ User name validator
    """
    def __init__(self, message=None):
        if not message:
            message = u'* Invalid user name'
        self.message = message

    def __call__(self, form, field):
        length = field.data and len(field.data) or 0
        if length == 0:
            pass
        elif length < 4 or length > 64:
            raise ValidationError(self.message)
        elif re.match(r'^[A-Za-z][A-Za-z0-9\._-]*$', field.data):
            pass
        else:
            raise ValidationError(self.message)

class PasswordValidator(object):
    """ Simple password validator for at least 8 characters with a lower, upper and digit
    """
    def __init__(self, message=None):
        if not message:
            message = u'* Invalid password'
        self.message = message

    def __call__(self, form, field):
        length = field.data and len(field.data) or 0
        if length < 8 or length > 64:
            raise ValidationError(self.message)
        elif re.match(r'(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}', field.data):
            pass
        else:
            raise ValidationError('Password must contain at least 8 characters, including UPPER/lowercase and numbers')

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
        elif length < 7 or length > 16:
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
        InputRequired(message="* Required"),
        Email(message="* Invalid")])
    password = PasswordField('Password', validators=[
        InputRequired(message="* Required"),
        Length(8, 64)])
    remember = BooleanField('Keep me logged in')
    submit = SubmitField('Login')

class InviteForm(FlaskForm):
    """ Invite a new user
    """
    email = StringField('Email', validators=[
        InputRequired(message="* Required"),
        Email(message="* Invalid")])
    phone = StringField('Phone', validators=[
        InputRequired(message="* Required"),
        PhoneNumberValidator()])
    user = StringField('Name', validators=[Length(2, 64)])
    submit = SubmitField('Invite')

class AcceptForm(FlaskForm):
    """ Accept invitation with token
    """
    action = HiddenField('Action')
    email = HiddenField('Email')
    token = HiddenField('Token')
    user = StringField('Name', validators=[Length(2, 64)])
    phone = StringField('Phone', validators=[
        InputRequired(message="* Required"),
        PhoneNumberValidator()])
    password = PasswordField('Password', validators=[
        InputRequired(message="* Required"),
        Length(8, 64)])
    newpassword = PasswordField('New Password', validators=[
        InputRequired(message="* Required"),
        EqualTo('confirm', message='* Passwords must match')
    ])
    code = StringField('Code', validators=[
        InputRequired(message="* Required"),
        Length(min=6, max=10)])
    confirm = PasswordField('Confirm password', validators=[InputRequired(message="* Required")])
    submit = SubmitField('Accept Invitation')

class ConfirmForm(FlaskForm):
    """ Confirm account with token
    """
    action = HiddenField('Action')
    email = HiddenField('Email')
    token = HiddenField('Token')
    code = StringField('Code', validators=[
        InputRequired(message="* Required"),
        Length(min=6, max=10)])
    submit = SubmitField('Confirm Account')

class VerifyForm(FlaskForm):
    """ Verify 2FA code
    """
    email = HiddenField('Email')
    token = StringField('Token', validators=[
        InputRequired(message="* Required"),
        Length(min=6, max=10)])
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
    email = HiddenField('Email')
    action = HiddenField('Action')
    phone = StringField('phone', [PhoneNumberValidator()])
    submit = SubmitField('Resend Token')

class RegistrationForm(FlaskForm):
    """ Register a new account
    """
    user = StringField('Name', validators=[Length(2, 64)])
    email = StringField('Email Address', validators=[
        InputRequired(message="* Required"),
        Email(message="* Invalid")])
    phone = StringField('Phone', validators=[
        InputRequired(message="* Required"),
        PhoneNumberValidator()])
    password = PasswordField('New password', validators=[
        InputRequired(message="* Required"),
        EqualTo('confirm', message='* Passwords must match')
    ])
    confirm = PasswordField('Confirm password', validators=[InputRequired(message="* Required")])
    token = StringField('Token', validators=[InputRequired(message="* Required")])
    accept_tos = BooleanField('I accept the TOS', validators=[InputRequired()])

class ChangePasswordForm(FlaskForm):
    """ Change password
    """
    email = HiddenField('Email')
    password = PasswordField('Password', validators=[
        InputRequired(message="* Required"),
        Length(8, 64)])
    newpassword = PasswordField('New Password', validators=[
        InputRequired(message="* Required"),
        EqualTo('confirm', message='* Passwords must match')
    ])
    confirm = PasswordField('Confirm password', validators=[InputRequired(message="* Required")])
    submit = SubmitField('Change Password')

class ForgotPasswordForm(FlaskForm):
    """ Request a password reset
    """
    email = StringField('Email Address', validators=[
        InputRequired(message="* Required"),
        Email(message="* Invalid")])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    """ Reset a password with token
    """
    email = HiddenField('Email')
    action = HiddenField('Action')
    token = HiddenField('Token')
    temppassword = PasswordField('Password', validators=[
        InputRequired(message="* Required"),
        Length(8, 64)])
    password = PasswordField('New Password', validators=[
        InputRequired(message="* Required"),
        EqualTo('confirm', message='* Passwords must match')
    ])
    confirm = PasswordField('Confirm password', validators=[InputRequired(message="* Required")])
    submit = SubmitField('Reset Password')
