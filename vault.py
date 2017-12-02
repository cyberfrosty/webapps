#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017 Alan Frost, All rights reserved.

Implementation of Vault Manager

"""

import simplejson as json

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
            html = '<ul class="fa-ul">\n'
            for box in vault.keys():
                html += '<li><input type="checkbox">' + box + '</li>\n'
            html += '</ul>\n'
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
            headings = box['headings']
            contents = box['contents']
            html = '<table style="width:100%">\n<tr>'
            for heading in headings:
                html += '  <th>' + heading + '</th>/n'
            for item in contents:
                html += '</tr>\n<tr>\n'
                for heading in headings:
                    if heading in item:
                        html += '  <td>' + item[heading] + '</td>'
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

if __name__ == '__main__':
    main()

