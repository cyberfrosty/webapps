#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017-2018 Alan Frost, All rights reserved.

Implementation of Vault Manager

"""

from __future__ import print_function

import os
import base64
import simplejson as json
from crypto import derive_key, decrypt_aes_gcm, encrypt_aes_gcm
from utils import generate_user_id, load_config, merge_dicts, read_csv
from awsutils import DynamoDB

class VaultManager(object):
    """ Vault Manager
    """

    def __init__(self, config):
        """ Initialize vault manager
        Args:
            config: dict of runtime config info
        """
        self.vaultdb = DynamoDB(config, config.get('vault'))
        self.userid_key = config.get('user_id_hmac').encode('utf-8')
        self.vaults = {}

    def generate_user_id(self, username):
        """ Generate unique userid from the username with an HMAC
        Args:
            username/email
        Returns:
            Generated 48 character base32 user id
        """
        return generate_user_id(self.userid_key, username.encode('utf-8'))

    def get_vault(self, userid):
        """ Get vault for specified user
        Args:
            userid: json file to load
        """
        if userid in self.vaults:
            vault = self.vaults[userid]
        else:
            vault = self.vaultdb.get_item('id', userid)
            if vault:
                self.vaults[userid] = vault
        return vault or {'error': 'Vault not found'}

    def patch_vault(self, userid, vault):
        """ Save vault for specified user (PATCH)
        Args:
            userid: json file to load
            vault: updated vault to save
        """
        current_vault = self.get_vault(userid)
        if current_vault:
            merge_dicts(current_vault, vault)
            self.vaults[userid] = current_vault
            return self.vaultdb.put_item(current_vault)
        return {'error': 'Vault not found'}

    def post_vault(self, userid, vault=None):
        """ Save vault for specified user (POST, or PUT) to DB
        Args:
            userid: json file to load
            vault: updated vault to save
        """
        # If None is passed, commit the current cached vault to DB
        if vault is None and userid in self.vaults:
            vault = self.vaults[userid]
        else:
            self.vaults[userid] = vault
        if vault:
            vault['id'] = userid
            return self.vaultdb.put_item(vault)
        return {'error': 'Vault not found'}

    def load_vault(self, userid, infile):
        """ Load json or csv data for vault
            ["accounts": {
              "headings": ["account", "username", "password"],
              "contents": [
                {"account": "Costco", "password", "pass1"},
                {"account": "Target", "username": "Joe", "password", "pass2"}
              ]
            },
            ...
            ]
        Args:
            file: json file to load
        """
        if infile.endswith('.csv'):
            box = read_csv(infile)
            box_name = infile.replace('.csv', '')
            vault = self.get_vault(userid)
            if vault:
                if box_name in vault:
                    safe_box = vault[box_name]
                    if 'contents' in safe_box:
                        merge_dicts(safe_box['contents'], box)
                    else:
                        safe_box['contents'] = box
                else:
                    vault[box_name] = box
            else:
                vault = {}
                vault[box_name] = box
        else:
            try:
                with open(infile) as json_file:
                    self.vaults[userid] = json.load(json_file)
            except (IOError, ValueError) as err:
                return {'error': 'Load vault file failed:' + str(err.message)}

    def encrypt_vault(self, userid, password):
        """ Encrypt the vault contents using a key derived from a password
        Args:
            password: to encrypt with
        """
        vault = self.get_vault(userid)
        if 'error' in vault:
            print(vault['error'])
            return

        mcf = derive_key(password.encode('utf-8'))
        fields = mcf.split('$')
        key = base64.b64decode(fields[4])
        mcf = '$pbkdf2$' + fields[2] + '$' + fields[3] + '$'
        for safebox in vault:
            box = vault[safebox]
            if isinstance(box, dict) and 'contents' in box:
                box_contents = json.dumps(box['contents'])
                iv = os.urandom(12)
                payload = iv + encrypt_aes_gcm(key, iv, box_contents)
                box['contents'] = base64.b64encode(payload)
                vault[safebox] = box
        vault['mcf'] = mcf
        self.vaults[userid] = vault

    def decrypt_vault(self, userid, password):
        """ Decrypt the vault contents using a key derived from a password
        Args:
            password: to decrypt with
        """
        vault = self.get_vault(userid)
        if 'error' in vault:
            print(vault['error'])
            return

        if 'mcf' in vault:
            mcf = derive_key(password.encode('utf-8'), vault['mcf'])
            fields = mcf.split('$')
            key = base64.b64decode(fields[4])
            for safebox in vault:
                box = vault[safebox]
                if isinstance(box, dict) and 'contents' in box and isinstance(box['contents'], str):
                    payload = base64.b64decode(box['contents'])
                    plaintext = decrypt_aes_gcm(key, payload[:12], payload[12:])
                    box['contents'] = json.loads(plaintext)
                    vault[safebox] = box
            self.vaults[userid] = vault

    def get_rendered_vault(self, vault):
        """ Render a vault as HTML
        Args:
            vault: optional vault as dictionary
        Returns:
            HTML
        """
        if vault is not None:
            contents = []
            columns = []
            html = '<div class="list-group" id="safebox-list">\n'
            for safebox in vault:
                box = vault[safebox]
                if isinstance(box, dict) and 'contents' in box:
                    title = box.get('title', safebox)
                    icon = box.get('icon', 'fa-eye')
                    html += '<a class="list-group-item" data-toggle="modal" href="#accessVault" id="' + safebox + '"><i class="fa ' + icon + ' fa-fw" aria-hidden="true"></i>&nbsp;' + title + '</a>\n'
                    contents.append((safebox, box.get('contents')))
                    columns.append((safebox, json.dumps(box.get('columns'))))
                    #html += '<button type="button" data-toggle="modal" data-target="#accessVault">Unlock</button>'
                    #html += '<li><a href="/vault?box=' + safebox + '">' + safebox + '</a></li>\n'
            html += '</div>\n'
            for item in columns:
                cid = item[0] + '-columns'
                html += '<div hidden id="' + cid + '">' + item[1] + '</div>\n'
            for item in contents:
                data = item[1] if isinstance(item[1], str) else json.dumps(item[1])
                cid = item[0] + '-contents'
                html += '<div hidden id="' + cid + '">' + data + '</div>\n'
        else:
            html = '<button id="create-vault" class="btn btn-primary"><i class="fa fa-plus fa-fw" aria-hidden="true"></i>&nbsp;Create</button>'
            html += '<button id="import-vault" class="btn btn-primary"><i class="fa fa-upload fa-fw" aria-hidden="true"></i>&nbsp;Import</button>'
        return html

    def get_rendered_box(self, vault, name):
        """ Render a vault box as HTML
        Args:
            vault: optional vault as dictionary
            name: name of the box
        Returns:
            HTML
        """

        if vault and name in vault:
            box = vault[name]
            headings = box['columns']
            contents = box['contents']
            html = '<table id="vault" style="width:100%">\n<tr>'
            for heading in headings:
                html += '  <th>' + heading['title'] + '</th>'
            for item in contents:
                html += '</tr>\n<tr>'
                for heading in headings:
                    if heading['field'] in item:
                        html += '  <td>' + item[heading['field']] + '</td>'
                    else:
                        html += '  <td></td>'
            html += '</tr>\n</table>\n'
        else:
            html = '<i class="fa fa-unlock" aria-hidden="true"></i>'
        return html

def main():
    """ Unit tests
    """
    config = load_config('config.json')
    manager = VaultManager(config)
    userid = manager.generate_user_id('yuki')
    manager.load_vault(userid, 'vault.json')
    print(manager.get_vault(userid))
    manager.post_vault(userid)
    manager.decrypt_vault(userid, 'Madman12')
    print(manager.get_vault(userid))
    print(manager.get_rendered_vault(None))
    print(manager.get_rendered_box(None, 'accounts'))
    print(manager.get_rendered_box(None, 'serial'))
    manager.encrypt_vault(userid, 'Madman12')
    print(manager.get_rendered_vault(None))
    manager.decrypt_vault(userid, 'Madman12')

if __name__ == '__main__':
    main()

