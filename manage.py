#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017 Alan Frost. All rights reserved.

Manage.py methods for starting and stopping servers
"""

import argparse
import re
import subprocess
import simplejson as json
from urlparse import urlparse
from awsutils import DynamoDB

def get_pid(port):
    """ Get pid of running server
    """
    try:
        portid = ':' + str(port)
        servers = subprocess.check_output(['lsof', '-i', portid])
    except subprocess.CalledProcessError, err:
        #print err + ' not running'
        return None
    except OSError, err:
        print 'lsof command not found'
        return None

    try:
        pid = re.findall('.*?[pP]ython\\s+[0-9]{4,7}', servers)[0].split(' ')[-1]
    except IndexError:
        pid = None
    pid = int(pid) if pid else None
    return pid

def init_env(config):
    """ Initialize a new environment with database tables, shared storage
    """
    if config.get('database') == 'DynamoDB':
        identity = DynamoDB(config.get('identity', 'Users'))
        identity.create_table(config.get('identity', 'Users'), 'id')
        sesssions = DynamoDB(config.get('sesssions', 'Sessions'))
        sesssions.create_table(config.get('sesssions', 'Sessions'), 'id')
        recipes = DynamoDB(config.get('recipes', 'Recipes'))
        recipes.create_table(config.get('recipes', 'Recipes'), 'id')

def load_config(config_file):
    """ Load the config.json file
    """
    config = None
    try:
        with open(config_file) as json_file:
            config = json.load(json_file)
    except IOError:
        print 'Config file not loaded: ' + config_file

    return config

def stop_server(service, port):
    """ Stop server listening on port
    """
    pid = get_pid(port)
    if pid:
        subprocess.check_output(['kill', '-15', str(pid)], stderr=subprocess.STDOUT)
        print service + ': stopped on port', port
    else:
        print service + ': no process listening on port', port

def start_tcp(config):
    """ Start TCP server
    """
    tcp = config.get('tcp')
    if tcp:
        fields = urlparse(tcp)
        port = fields.port
        pid = get_pid(port)
        if pid:
            print 'TCP: process', pid, 'already listening on port', port
        else:
            subprocess.Popen(['python', 'tcpserver.py'])
    else:
        print 'TCP: no service in config'

def stop_tcp(config):
    """ Stop TCP server
    """
    tcp = config.get('tcp')
    if tcp:
        fields = urlparse(tcp)
        port = fields.port
        stop_server('TCP', port)
    else:
        print 'TCP: no service in config'

def start_websocket(config):
    """ Start websocket server for events
    """
    websocket = config.get('websocket')
    if websocket:
        fields = urlparse(websocket)
        port = fields.port
        pid = get_pid(port)
        if pid:
            print 'WS: process', pid, 'already listening on port', port
        else:
            subprocess.Popen(['python', 'websocket.py'])
    else:
        print 'WS: no service in config'

def stop_websocket(config):
    """ Stop websocket server
    """
    websocket = config.get('websocket')
    if websocket:
        fields = urlparse(websocket)
        port = fields.port
        stop_server('WS', port)
    else:
        print 'WS: no service in config'

def start_http():
    """ Start HTTP server for serving pages
    """
    port = '8080'
    pid = get_pid(port)
    if pid:
        print 'HTTP: process', pid, 'already listening on port', port
    else:
        subprocess.Popen(['python', 'webapp.py'])

def stop_http():
    """ Stop HTTP server
    """
    port = '8080'
    stop_server('HTTP', port)

def parse_options():
    """ Parse command line options
    """
    parser = argparse.ArgumentParser(description='Frosty management app')
    group = parser.add_argument_group('authentication')
    group.add_argument('--user', action="store")
    group.add_argument('--password', action="store")
    parser.add_argument('--config', action='store', default='config.json', help='config.json')
    parser.add_argument('--http', action='store_true', help='Start or stop web server')
    parser.add_argument('--tcp', action='store_true', help='Start or stop TCP server')
    parser.add_argument('--websocket', action='store_true', help='Start or stop websocket server')
    parser.add_argument('command', action='store', help='init, start, stop')
    return parser.parse_args()

def main():
    """ Main program
    """
    options = parse_options()
    config = load_config(options.config)
    if options.command == 'start':
        if options.http is True:
            start_http()
        if options.tcp is True:
            start_tcp(config)
        if options.websocket is True:
            start_websocket(config)
    elif options.command == 'stop':
        if options.http is True:
            stop_http()
        if options.tcp is True:
            stop_tcp(config)
        if options.websocket is True:
            stop_websocket(config)
    elif options.command == 'init':
        init_env(config)

if __name__ == '__main__':
    main()
