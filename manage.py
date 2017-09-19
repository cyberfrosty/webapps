#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017 Alan Frost. All rights reserved.

Manage.py methods for initialization, starting and stopping servers
"""

import argparse
import json
import re
import subprocess
from awsutils import DynamoDB

def get_pid(port):
    """ Get pid of running server
    Args:
        port that the service is listening on
    """
    try:
        portid = ':' + str(port)
        servers = subprocess.check_output(['lsof', '-i', portid])
    except subprocess.CalledProcessError, err:
        #print err + ' not running'
        return None
    except OSError, err:
        print 'lsof command not found', err
        return None

    try:
        pid = re.findall('.*?[pP]ython\\s+[0-9]{4,7}', servers)[0].split(' ')[-1]
    except IndexError:
        pid = None
    pid = int(pid) if pid else None
    return pid

def init_env(config):
    """ Initialize a new environment with database tables, shared storage
    Args:
        config dictionary
    """
    if config.get('users'):
        database = DynamoDB(config, config.get('users'))
        database.create_table('id')
    if config.get('sessions'):
        database = DynamoDB(config, config.get('sessions'))
        database.create_table('id')
    if config.get('recipes'):
        database = DynamoDB(config, config.get('recipes'))
        database.create_table('id')

def load_config(config_file):
    """ Load the config.json file
    Args:
        config filename
    """
    config = None
    try:
        with open(config_file) as json_file:
            config = json.load(json_file)
    except (IOError, ValueError) as err:
        print('Load of config file failed:', err.message)

    return config

def stop_server(service, port):
    """ Stop server listening on port
    Args:
        service name
        port that the service is listening on
    """
    pid = get_pid(port)
    if pid:
        subprocess.check_output(['kill', '-15', str(pid)], stderr=subprocess.STDOUT)
        print service + ': stopped on port', port
    else:
        print service + ': no process listening on port', port

def start_http(config):
    """ Start HTTP server
    Args:
        config dictionary
    """
    port = config.get('port', 8080)
    pid = get_pid(port)
    if pid:
        print 'HTTP: process', pid, 'already listening on port', port
    else:
        subprocess.Popen(['python', 'webapp.py'])

def stop_http(config):
    """ Stop HTTP server with SIGTERM
    Args:
        config dictionary
    """
    port = config.get('port', 8080)
    stop_server('REST', port)

def parse_options():
    """ Parse command line options
    """
    parser = argparse.ArgumentParser(description='Management app')
    group = parser.add_argument_group('authentication')
    group.add_argument('-u', '--user', action="store")
    group.add_argument('-p', '--password', action="store")
    parser.add_argument('--config', action='store', default='config.json', help='config.json')
    parser.add_argument('command', action='store', help='init, start, stop, restart')
    return parser.parse_args()

def start_servers(config):
    """ Start servers
    """
    start_http(config)

def stop_servers(config):
    """ Stop servers
    """
    stop_http(config)

def main():
    """ Main program
    """
    options = parse_options()
    config = load_config(options.config)
    if options.command == 'start':
        start_servers(config)
    elif options.command == 'stop':
        stop_servers(config)
    elif options.command == 'restart':
        stop_servers(config)
        start_servers(config)
    elif options.command == 'init':
        init_env(config)

if __name__ == '__main__':
    main()
