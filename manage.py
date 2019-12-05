#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017-2018 Alan Frost. All rights reserved.

Manage.py methods for initialization, starting and stopping servers
"""

from __future__ import print_function
import argparse
import base64
import os
import re
import subprocess
import json
import requests
from awsutils import DynamoDB
from crypto import derive_key, encrypt_aes_gcm
from utils import load_config, read_csv, write_csv

def get_pid(port):
    """ Get pid of running server
    Args:
        port that the service is listening on
    """
    try:
        portid = ':' + str(port)
        servers = subprocess.check_output(['lsof', '-i', portid])
    except subprocess.CalledProcessError, err:
        #print(err + ' not running')
        return None
    except OSError, err:
        print('lsof command not found', err)
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
    if config.get('vault'):
        database = DynamoDB(config, config.get('vault'))
        database.create_table('id')
    if config.get('recipes'):
        database = DynamoDB(config, config.get('recipes'))
        database.create_table('id')

def import_vault(csv_filename, password):
    """ Import vault content from CSV file
    Args:
        csv_filename
        password
    """
    safebox = csv_filename.replace('.csv', '')
    items = read_csv(csv_filename)
    if password:
        mcf = derive_key(password.encode('utf-8'))
        fields = mcf.split('$')
        key = base64.b64decode(fields[4])
        mcf = '$pbkdf2$' + fields[2] + '$' + fields[3] + '$'
        iv = os.urandom(12)
        contents = '['
        for item in items:
            contents += json.dumps(item) + ','
        contents = contents[:-1] + ']'
        payload = iv + encrypt_aes_gcm(key, iv, contents)
        contents = base64.b64encode(payload)
        print(contents)
        print(mcf)
    else:
        for item in items:
            print(json.dumps(item))

def stop_server(service, port):
    """ Stop server listening on port
    Args:
        service name
        port that the service is listening on
    """
    pid = get_pid(port)
    if pid:
        subprocess.check_output(['kill', '-15', str(pid)], stderr=subprocess.STDOUT)
        print(service + ': stopped on port', port)
    else:
        print(service + ': no process listening on port', port)

def start_http(config):
    """ Start HTTP server
    Args:
        config dictionary
    """
    port = config.get('port', 8080)
    pid = get_pid(port)
    if pid:
        print('HTTP: process', pid, 'already listening on port', port)
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
    parser.add_argument('-f', '--file', action="store")
    parser.add_argument('-s', '--site', action="store", default='https://cyberfrosty.com')
    parser.add_argument('--config', action='store', default='config.json', help='config.json')
    parser.add_argument('command', action='store', help='check, init, start, stop, restart')
    return parser.parse_args()

def start_servers(config):
    """ Start servers
    """
    start_http(config)

def stop_servers(config):
    """ Stop servers
    """
    stop_http(config)

def check_http(site):
    """ Check a server and measure response time
    Args:
        site name to check
    """
    url = site + '/api/server.info'
    try:
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            try:
                info = response.json()
                info['latency'] = response.elapsed.total_seconds()
            except ValueError as err:
                info = {'latency': response.elapsed.total_seconds()}
            print(json.dumps(info))
        else:
            print(response.status_code, response.elapsed.total_seconds())
    except requests.ConnectionError as err:
        print(err)

def main():
    """ Main program
    """
    options = parse_options()
    config = load_config(options.config)
    if options.command == 'check':
        check_http(options.site)
    elif options.command == 'start':
        start_servers(config)
    elif options.command == 'stop':
        stop_servers(config)
    elif options.command == 'restart':
        stop_servers(config)
        start_servers(config)
    elif options.command == 'import':
        import_vault(options.file, options.password)
    elif options.command == 'init':
        init_env(config)

if __name__ == '__main__':
    main()
