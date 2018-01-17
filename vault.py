#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017-2018 Alan Frost, All rights reserved.

Implementation of Vault Manager

"""

import os
import base64
import simplejson as json
from crypto import derive_key, decrypt_aes_gcm, encrypt_aes_gcm

class VaultManager(object):
    """ Vault Manager
    """

    def __init__(self, vault=None):
        self.vault = vault

    def load_vault(self, infile):
        """ Load json data for vault
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
        try:
            with open(infile) as json_file:
                self.vault = json.load(json_file)
        except (IOError, ValueError) as err:
            print('Load of vault file failed:', err.message)

    def encrypt_vault(self, password):
        """ Encrypt the vault contents using a key derived from a password
        Args:
            password: to encrypt with
        """
        mcf = derive_key(password.encode('utf-8'))
        fields = mcf.split('$')
        key = base64.b64decode(fields[4])
        mcf = '$pbkdf2$' + fields[2] + '$' + fields[3] + '$'
        iv = os.urandom(12)
        for safebox in self.vault:
            box = self.vault[safebox]
            if isinstance(box, dict) and 'contents' in box:
                box_contents = json.dumps(box['contents'])
                payload = iv + encrypt_aes_gcm(key, iv, box_contents)
                box['contents'] = base64.b64encode(payload)
                self.vault[safebox] = box
        self.vault['mcf'] = mcf

    def decrypt_vault(self, password):
        """ Decrypt the vault contents using a key derived from a password
        Args:
            password: to decrypt with
        """
        if 'mcf' in self.vault:
            mcf = derive_key(password.encode('utf-8'), self.vault['mcf'])
            fields = mcf.split('$')
            key = base64.b64decode(fields[4])
            print self.vault
            for safebox in self.vault:
                box = self.vault[safebox]
                if isinstance(box, dict) and 'contents' in box:
                    payload = base64.b64decode(box['contents'])
                    plaintext = decrypt_aes_gcm(key, payload[:12], payload[12:])
                    print plaintext

    def get_rendered_vault(self, vault):
        """ Render a vault as HTML
        Args:
            vault: optional vault as dictionary
        Returns:
            HTML
        """
        if not vault and self.vault:
            vault = self.vault
        if vault is not None:
            contents = []
            html = '<div class="list-group" id="safebox-list">\n'
            for safebox in vault:
                box = vault[safebox]
                if isinstance(box, dict) and 'contents' in box:
                    title = box.get('title', safebox)
                    icon = box.get('icon', 'fa-eye')
                    html += '<a class="list-group-item" data-toggle="modal" href="#accessVault" id="' + safebox + '"><i class="fa ' + icon + ' fa-fw" aria-hidden="true"></i>&nbsp;' + title + '</a>'
                    contents.append((safebox, box.get('contents')))
                    #html += '<button type="button" data-toggle="modal" data-target="#accessVault">Unlock</button>'
                    #html += '<li><a href="/vault?box=' + safebox + '">' + safebox + '</a></li>\n'
            html += '</div>\n'
            for item in contents:
                data = item[1] if type(item[1]) is str else json.dumps(item[1])
                cid = item[0] + '-contents'
                html += '<div hidden id="' + cid + '">' + data + '</div>\n'
            html += '<div id="safebox-table"></div>\n'
        else:
            html = '<textarea id="vault">Encrypted content</textarea>'
        return html

    def get_rendered_box(self, vault, name):
        """ Render a vault box as HTML
        Args:
            vault: optional vault as dictionary
            name: name of the box
        Returns:
            HTML
        """

        if not vault and self.vault:
            vault = self.vault
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
    manager = VaultManager()
    manager.load_vault('vault.json')
    print manager.get_rendered_vault(None)
    print manager.get_rendered_box(None, 'accounts')
    print manager.get_rendered_box(None, 'serial')
    manager.encrypt_vault('Madman12')
    print manager.get_rendered_vault(None)
    manager.decrypt_vault('Madman12')

if __name__ == '__main__':
    main()

