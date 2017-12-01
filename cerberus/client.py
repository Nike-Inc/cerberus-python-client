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
from . import CerberusClientException, CLIENT_VERSION
import ast
import json


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
        self.HEADERS['X-Cerberus-Client'] = 'CerberusPythonClient/' + CLIENT_VERSION

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

    def get_roles(self):
        """Returns all the roles (IAM or User Groups) that can be granted to a safe deposit box.

        Roles are permission levels that are granted to IAM or User Groups.  Associating the id for the write role
          would allow that IAM or User Group to write in the safe deposit box."""
        roles_resp = requests.get(self.cerberus_url + '/v1/role',
                                headers=self.HEADERS)

        self.throw_if_bad_response(roles_resp)
        return roles_resp.json()

    def get_role(self, key):
        """Returns id of named role."""

        json_resp = self.get_roles() 
        for item in json_resp:
            if key in item["name"]:
                return item["id"]
        raise CerberusClientException("Key '%s' not found" % key)

    def list_roles(self):
        """Simplified version of get_roles that returns a dict of just name: id for the roles"""

        json_resp = self.get_roles()
        temp_dict = {}
        for item in json_resp:
            temp_dict[item["name"]] = item["id"]
        return temp_dict

    def get_categories(self):
        """ Return a list of categories that a safe deposit box can belong to"""
        sdb_resp = requests.get(self.cerberus_url + '/v1/category',
                                headers=self.HEADERS)

        self.throw_if_bad_response(sdb_resp)
        return sdb_resp.json()

    def create_sdb(self, name, category_id, owner, description="", user_group_permissions=None,
                   iam_principal_permissions=None):
        """Create a safe deposit box.

        You need to refresh your token before the iam role is granted permission to the new safe deposit box.
        Keyword arguments:
            name (string) -- name of the safe deposit box
            category_id (string) -- category id that determines where to store the sdb. (ex: shared, applications)
            owner (string) -- AD group that owns the safe deposit box
            description (string) -- Description of the safe deposit box
            user_group_permissions (list) -- list of dictionaries containing the key name and maybe role_id
            iam_principal_permissions (list) -- list of dictionaries containing the key name iam_principal_arn
            and role_id
        """

        # Do some sanity checking
        if user_group_permissions is None:
            user_group_permissions = []
        if iam_principal_permissions is None:
            iam_principal_permissions = []
        if list != type(user_group_permissions):
            raise(TypeError('Expected list, but got ' + str(type(user_group_permissions))))
        if list != type(iam_principal_permissions):
            raise(TypeError('Expected list, but got ' + str(type(iam_principal_permissions))))
        temp_data = {
            "name": name,
            "description": description,
            "category_id": category_id,
            "owner": owner,
        }
        if len(user_group_permissions) > 0:
            temp_data["user_group_permissions"] = user_group_permissions
        if len(iam_principal_permissions) > 0:
            temp_data["iam_principal_permissions"] = iam_principal_permissions
        data = json.encoder.JSONEncoder().encode(temp_data)
        sdb_resp = requests.post(self.cerberus_url + '/v2/safe-deposit-box', data=str(data), headers=self.HEADERS)

        self.throw_if_bad_response(sdb_resp)
        return sdb_resp.json()

    def delete_sdb(self, sdb_id):
        """ Delete a safe deposit box specified by id

        Keyword arguments:
        sdb_id -- this is the id of the safe deposit box, not the path."""
        sdb_resp = requests.delete(self.cerberus_url + '/v2/safe-deposit-box/' + sdb_id,
                                   headers=self.HEADERS)
        self.throw_if_bad_response(sdb_resp)
        return sdb_resp

    def get_sdbs(self):
        """ Return a list of each SDB the client is authorized to view"""
        sdb_resp = requests.get(self.cerberus_url + '/v2/safe-deposit-box',
                                headers=self.HEADERS)

        self.throw_if_bad_response(sdb_resp)
        return sdb_resp.json()

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
        """ Return the ID for the given safe deposit box.

        Keyword arguments:
        sdb -- This is the name of the safe deposit box, not the path"""
        json_resp = self.get_sdbs()
        for r in json_resp:
            if r['name'] == sdb:
                return str(r['id'])

        # If we haven't returned yet then we didn't find what we were
        # looking for.
        raise CerberusClientException("'%s' not found" % sdb)

    def get_sdb_id_by_path(self, sdb_path):
        """ Given the path, return the ID for the given safe deposit box."""
        json_resp = self.get_sdbs()

        # Deal with the supplied path possibly missing an ending slash
        path = sdb_path
        if not sdb_path.endswith('/'):
            path = sdb_path + '/'

        for r in json_resp:
            if r['path'] == path:
                return str(r['id'])

        # If we haven't returned yet then we didn't find what we were
        # looking for.
        raise CerberusClientException("'%s' not found" % sdb_path)

    def get_sdb_by_id(self, sdb_id):
        """ Return the details for the given safe deposit box id

        Keyword arguments:
        sdb_id -- this is the id of the safe deposit box, not the path.
        """
        sdb_resp = requests.get(self.cerberus_url + '/v2/safe-deposit-box/' + sdb_id,
                                headers=self.HEADERS)

        self.throw_if_bad_response(sdb_resp)

        return sdb_resp.json()

    def get_sdb_by_path(self, sdb_path):
        """ Return the details for the given safe deposit box path.
        
        Keyword arguments:
        sdb_path -- this is the path for the given safe deposit box.  ex: ('shared/my-test-box')
        """
        return self.get_sdb_by_id(self.get_sdb_id_by_path(sdb_path))

    def get_sdb_by_name(self, sdb_name):
        """ Return the details for the given safe deposit box name.
        
        Keyword arguments:
        sdb_name -- this is the name for the given safe deposit box.  ex: ('My Test Box')
        """
        return self.get_sdb_by_id(self.get_sdb_id(sdb_name))


    def update_sdb(self, sdb_id, owner=None, description=None, user_group_permissions=None,
                   iam_principal_permissions=None):
        """Update a safe deposit box.

        Keyword arguments:

            owner (string) -- AD group that owns the safe deposit box
            description (string) -- Description of the safe deposit box
            user_group_permissions (list) -- list of dictionaries containing the key name and maybe role_id
            iam_principal_permissions (list) -- list of dictionaries containing the key name iam_principal_arn
            and role_id
        """
        # Grab current data
        old_data = self.get_sdb_by_id(sdb_id)

        # Assemble information to update
        temp_data = {}
        keys = ('owner', 'description','iam_principal_permissions', 'user_group_permissions')
        for k in keys:
            if k in old_data:
                temp_data[k] = old_data[k]
        if owner is not None:
            temp_data["owner"] = owner
        if description is not None:
            temp_data["description"] = description
        if user_group_permissions is not None and len(user_group_permissions) > 0:
            temp_data["user_group_permissions"] = user_group_permissions
        if iam_principal_permissions is not None and len(iam_principal_permissions) > 0:
            temp_data["iam_principal_permissions"] = iam_principal_permissions

        data = json.encoder.JSONEncoder().encode(temp_data)
        sdb_resp = requests.put(self.cerberus_url + '/v2/safe-deposit-box/' + sdb_id, data=str(data),
                                headers=self.HEADERS)

        self.throw_if_bad_response(sdb_resp)
        return sdb_resp.json()

    def delete_secret(self, vault_path):
        """Delete a secret from the given vault path"""
        secret_resp = requests.delete(self.cerberus_url + '/v1/secret/' + vault_path,
                                      headers=self.HEADERS)
        self.throw_if_bad_response(secret_resp)
        return secret_resp

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

    def list_secrets(self, vault_path):
        """Returns json secrets based on the vault_path, this will list keys in a folder"""
        secret_resp = requests.get(self.cerberus_url + '/v1/secret/' + vault_path + '?list=true',
                                   headers=self.HEADERS)
        self.throw_if_bad_response(secret_resp)
        return secret_resp.json()

    def put_secret(self, vault_path, secret, merge=True):
        """Write secret(s) to a vault_path provided a dictionary of key/values

        Keyword arguments:
        vault_path -- full path in the secret deposit box that contains the key
        secret -- A dictionary containing key/values to be written at the vault_path
        merge -- Boolean that determines if the provided secret keys should be merged with
            the values already present at the vault_path.  If False the keys will
            completely overwrite what was stored at the vault_path. (default True)
        """
        # json encode the input.  Cerberus is sensitive to double vs single quotes.
        # an added bonus is that json encoding transforms python2 unicode strings
        # into a compatible format.
        data = json.encoder.JSONEncoder().encode(key)
        if merge:
            data = self.secret_merge(vault_path, key)
        secret_resp = requests.put(self.cerberus_url + '/v1/secret/' + vault_path,
                                   data=str(data), headers=self.HEADERS)
        self.throw_if_bad_response(secret_resp)
        return secret_resp

    def secret_merge(self, vault_path, key):
        """Compares key/values at vault_path and merges them.  New values will overwrite old."""
        get_resp = requests.get(self.cerberus_url + '/v1/secret/' + vault_path, headers=self.HEADERS)
        temp_key = {}
        # Ignore a return of 404 since it means the key might not exist
        if get_resp.status_code == requests.codes.bad and get_resp.status_code not in [403, 404]:
            self.throw_if_bad_response(get_resp)
        elif get_resp.status_code in [403, 404]:
            temp_key = {}
        else:
            temp_key = get_resp.json()['data']
        # Allow key to be either a string describing a dict or a dict.
        if type(key) == str:
            temp_key.update(ast.literal_eval(key))
        else:
            temp_key.update(key)
        # This is a bit of a hack to get around python 2 treating unicode strings
        # differently.  Cerberus will throw a 400 if we try to post python 2 style
        # unicode stings as the payload.
        combined_key = json.encoder.JSONEncoder().encode(temp_key)
        return combined_key

    def throw_if_bad_response(self, response):
        """Throw an exception if the Cerberus response is not successful."""
        try:
            response.raise_for_status()
        except RequestException as e:
            raise CerberusClientException(str(e))
