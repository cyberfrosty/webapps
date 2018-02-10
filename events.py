#!/usr/bin python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2018 Alan Frost, Inc. All rights reserved.

Utility methods
"""

from __future__ import print_function

from datetime import datetime
import simplejson as json
import pytz

from utils import (base58encode_int, generate_random_int)

ACTIONS = {
    'server.info': 'GET',
    'login': 'POST',
    'logout': 'DELETE',
    'recipes': 'GET',
    'upload': 'POST',
    'confirm': 'POST',
    'verify': 'POST',
    'change': 'POST',
    'resend': 'POST',
    'invite': 'POST',
    'reset': 'POST',
    'register': 'POST',
    'forgot': 'POST',
    'message.post': 'POST',
    'message.get': 'GET',
}

def get_timestamp():
    """ Get the current UTC timestamp
    Return:
        timestamp: int
    """
    timestamp = int((datetime.now(tz=pytz.utc) -
                     datetime(1970, 1, 1, tzinfo=pytz.utc)).total_seconds())
    return timestamp

def event_nonce():
    """ Generate a random 32 bit integer encoded as base58
    Return:
        nonce: base58 string
    """
    return base58encode_int(generate_random_int())

class EventManager(object):
    """ Event manager class
    """
    def __init__(self, config):
        """ Constructor, get AWS resource and table.
        Args:
            config: dict of config info
        """
        self.event_file = None
        if config.get('events', None):
            try:
                self.event_file = open(config.get('events'), 'a')
                print('Logging events to', config.get('events'))
            except (IOError) as err:
                print('Open of events file failed:', err.message)

    def flush_events(self):
        """ Flush any unwritten events to the event file
        """
        if self.event_file:
            self.event_file.flush()

    def log_event(self, event):
        """ Log an event
        Args:
            event: json dictionary
        """
        if self.event_file:
            event['ts'] = get_timestamp()
            self.event_file.write(json.dumps(event) + '\n')

    def web_event(self, action, uid, **kwargs):
        """ Make and log a web event
            event: {"uid": "SZO2HM6...", "type": "recipe", "ts": 1472597386, "recipe": "Korean Meatballs"}
        Args:
            action: recipe, change
            uid: User account identifier
            kwargs: Additional parameters
        """
        event = {'type': action, 'uid': uid}
        if kwargs is not None:
            for key, value in kwargs.iteritems():
                event[key] = value
        self.log_event(event)

    def error_event(self, action, uid, message, **kwargs):
        """ Make and log an error event
            event: {"uid": "SZO2HM6...", "type": "login", "ts": 1472597386, "error": "Unable to validate"}
        Args:
            action: login, change
            uid: User account identifier
            message: the error message
            kwargs: Additional parameters
        """
        event = {'type': action, 'uid': uid, 'error': message}
        if kwargs is not None:
            for key, value in kwargs.iteritems():
                event[key] = value
        self.log_event(event)

    def action_event(self, action, uid, **kwargs):
        """ Make an action event
        Args:
            action: REST API method
            uid: User account identifier
        Return:
            event: {"eid": "n6uQRCGv", "type": "file.upload", "ts": "1472597386.405150",
                    "account": "SZO2HM6...", "account":"alan"}
        """
        event = dict(type=action,
                     eid=event_nonce(),
                     account=account,
                     ts=get_timestamp())
        if kwargs is not None:
            for key, value in kwargs.iteritems():
                event[key] = value
        self.log_event(event)

    def replyto_event(self, nonce, account, **kwargs):
        """ Make a reply event
        Args:
            nonce: matching id reply is in reponse to
            uid: User account identifier
            kwargs:
                identifier: identity to send reply to
                status: ok, read, ...
        Return:
            event: {"eid": "n6uQRCGv", "type": "reply", "ts": 1472597386,
                    "SZO2HM6...": "me", "status": "ok"}
        """
        event = dict(type='reply',
                     eid=nonce,
                     account=account,
                     ts=get_timestamp())
        if kwargs is not None:
            for key, value in kwargs.iteritems():
                event[key] = value
        self.log_event(event)

    def make_rest(self, url, event, **kwargs):
        """ Make an REST URL call for an event
        Args:
            url: Base url for api call
            event: JSON event {"eid": "n6uQRCGv", "type": "file.upload", "ts": 1472597386,
                               "uid": "me", "group": "mygroup"}
            kwargs: group=groupname
                    after=timestamp
                    before=timestamp
        Return:
            rest: dictionary {'url': 'base_url/api/method', 'method': 'POST', 'params': {}}
        """
        rest = {}
        after = kwargs.pop('after', None)
        if after:
            after = datetime.fromtimestamp(float(after), tz=pytz.utc)
        before = kwargs.pop('before', None)
        if before:
            before = datetime.fromtimestamp(float(before), tz=pytz.utc)
        try:
            jevent = json.loads(event)
            if jevent and jevent.get('type') in ACTIONS:
                rest['url'] = url + '/api/' + jevent['type']
                rest['method'] = ACTIONS[jevent['type']]
                if 'eid' in jevent:
                    del jevent['eid']
                del jevent['type']
                del jevent['ts']
                del jevent['account']
                rest['params'] = jevent
        except (KeyError, ValueError):
            pass
        return rest

def main():
    """ Unit tests
    """

if __name__ == '__main__':
    main()

