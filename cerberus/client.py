"""
Copyright 2016-present Nike, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
You may not use this file except in compliance with the License.
You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and* limitations under the License.*
"""

import requests
from requests.exceptions import RequestException

from .aws_auth import AWSAuth
from .user_auth import UserAuth
from . import CerberusClientException


class CerberusClient(object):
    """ Cerberus Python Client for interacting with
        Cerberus APIs and Vault. Authentication is done
        via the Auth Classes"""
    HEADERS = {'Content-Type': 'application/json'}

    def __init__(self, cerberus_url, username=None, password=None, role_arn=None, region=None):
        """Username and password are optional, they are not needed
           for IAM Role Auth"""
        self.cerberus_url = cerberus_url
        self.username = username or ""
        self.password = password or ""
        self.role_arn = role_arn
        self.region = region
        self.token = None
        self.set_token()

        self.HEADERS['X-Vault-Token'] = self.token

    def set_token(self):
        """Set the Vault token based on auth type"""
        if self.username:
            ua = UserAuth(self.cerberus_url, self.username, self.password)
            self.token = ua.get_token()
        else:
            awsa = AWSAuth(self.cerberus_url, role_arn=self.role_arn, region=self.region)
            self.token = awsa.get_token()

    def get_token(self):
        """Returns a client token from Cerberus"""
        return self.token

    def get_sdb_path(self, sdb):
        """Returns the path for a SDB"""
        sdb_id = self.get_sdb_id(sdb)
        sdb_resp = requests.get(
            self.cerberus_url + '/v1/safe-deposit-box/' + sdb_id + '/',
            headers=self.HEADERS
        )

        self.throw_if_bad_response(sdb_resp)

        return sdb_resp.json()['path']

    def get_sdb_keys(self, path):
        """Returns the keys for a SDB, which are need for the full vault path"""
        list_resp = requests.get(
            self.cerberus_url + '/v1/secret/' + path + '/?list=true',
            headers=self.HEADERS
        )

        self.throw_if_bad_response(list_resp)

        return list_resp.json()['data']['keys']

    def get_sdb_id(self, sdb):
        """ Return the ID for the given safety deposit box"""
        sdb_resp = requests.get(self.cerberus_url + '/v1/safe-deposit-box',
                                headers=self.HEADERS)

        self.throw_if_bad_response(sdb_resp)

        for r in sdb_resp.json():
            if r['name'] == sdb:
                return str(r['id'])

        # If we haven't returned yet then we didn't find what we were
        # looking for.
        raise CerberusClientException("'%s' not found" % sdb)

    def get_secret(self, vault_path, key):
        """Returns the secret based on the vault_path and key"""
        secret_resp_json = self.get_secrets(vault_path)

        if key in secret_resp_json['data']:
            return secret_resp_json['data'][key]
        else:
            raise CerberusClientException("Key '%s' not found" % key)

    def get_secrets(self, vault_path):
        """Returns json secrets based on the vault_path"""
        secret_resp = requests.get(self.cerberus_url + '/v1/secret/' + vault_path,
                                   headers=self.HEADERS)

        self.throw_if_bad_response(secret_resp)

        return secret_resp.json()

    def throw_if_bad_response(self, response):
        """Throw an exception if the Cerberus response is not successful."""
        try:
            response.raise_for_status()
        except RequestException as e:
            raise CerberusClientException(str(e))
