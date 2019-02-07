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

from .aws_auth import AWSAuth
from .user_auth import UserAuth
from . import CerberusClientException, CLIENT_VERSION
from .util import throw_if_bad_response, get_with_retry, post_with_retry, put_with_retry, delete_with_retry, head_with_retry
import ast
import json
import warnings
import os


class CerberusClient(object):
    """ Cerberus Python Client for interacting with
        Cerberus APIs. Authentication is done
        via the Auth Classes"""
    HEADERS = {'Content-Type': 'application/json'}

    def __init__(self, cerberus_url, username=None, password=None, region='us-west-2', token=None, aws_session=None):
        """
        Username and password are optional, they are not needed for IAM Role Auth. If aws_session is set with
        a botocore.session.Session object, the Cerberus client will sign the request using the session provided
        instead of the default session.
        """
        self.cerberus_url = cerberus_url
        self.username = username or ""
        self.password = password or ""
        self.region = region
        self.token = token
        self.aws_session = aws_session
        if self.token is None:
            self._set_token()

        self.HEADERS['X-Cerberus-Token'] = self.token
        self.HEADERS['X-Cerberus-Client'] = 'CerberusPythonClient/' + CLIENT_VERSION

    def _add_slash(self, string=None):
        """ if a string doesn't end in a '/' add one """
        if(not str.endswith(string, '/')):
            return str.join('', [string, '/'])
        return str(string)

    def _set_token(self):
        """Set the Cerberus token based on auth type"""
        try:
            self.token = os.environ['CERBERUS_TOKEN']
            print("Overriding Cerberus token with environment variable.")
            return
        except:
            pass
        if self.username:
            ua = UserAuth(self.cerberus_url, self.username, self.password)
            self.token = ua.get_token()
        else:
            awsa = AWSAuth(self.cerberus_url, region=self.region, aws_session=self.aws_session)
            self.token = awsa.get_token()

    def get_token(self):
        """Return a client token from Cerberus"""
        return self.token

    def get_roles(self):
        """Return all the roles (IAM or User Groups) that can be granted to a safe deposit box.

        Roles are permission levels that are granted to IAM or User Groups.  Associating the id for the write role
          would allow that IAM or User Group to write in the safe deposit box."""
        roles_resp = get_with_retry(self.cerberus_url + '/v1/role',
                                  headers=self.HEADERS)

        throw_if_bad_response(roles_resp)
        return roles_resp.json()

    def get_role(self, key):
        """Return id of named role."""

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
        sdb_resp = get_with_retry(self.cerberus_url + '/v1/category',
                                headers=self.HEADERS)

        throw_if_bad_response(sdb_resp)
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
        sdb_resp = post_with_retry(self.cerberus_url + '/v2/safe-deposit-box', data=str(data), headers=self.HEADERS)

        throw_if_bad_response(sdb_resp)
        return sdb_resp.json()

    def delete_sdb(self, sdb_id):
        """ Delete a safe deposit box specified by id

        Keyword arguments:
        sdb_id -- this is the id of the safe deposit box, not the path."""
        sdb_resp = delete_with_retry(self.cerberus_url + '/v2/safe-deposit-box/' + sdb_id,
                                   headers=self.HEADERS)
        throw_if_bad_response(sdb_resp)
        return sdb_resp

    def get_sdbs(self):
        """ Return a list of each SDB the client is authorized to view"""
        sdb_resp = get_with_retry(self.cerberus_url + '/v2/safe-deposit-box',
                                headers=self.HEADERS)

        throw_if_bad_response(sdb_resp)
        return sdb_resp.json()

    def get_sdb_path(self, sdb):
        """Return the path for a SDB"""
        sdb_id = self.get_sdb_id(sdb)
        sdb_resp = get_with_retry(
            self.cerberus_url + '/v1/safe-deposit-box/' + sdb_id + '/',
            headers=self.HEADERS
        )

        throw_if_bad_response(sdb_resp)

        return sdb_resp.json()['path']

    def get_sdb_keys(self, path):
        """Return the keys for a SDB, which are need for the full secure data path"""
        list_resp = get_with_retry(
            self.cerberus_url + '/v1/secret/' + path + '/?list=true',
            headers=self.HEADERS
        )

        throw_if_bad_response(list_resp)

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
        path = self._add_slash(sdb_path)

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
        sdb_resp = get_with_retry(self.cerberus_url + '/v2/safe-deposit-box/' + sdb_id,
                                headers=self.HEADERS)

        throw_if_bad_response(sdb_resp)

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

    def get_sdb_secret_version_paths(self, sdb_id):
        """ Get SDB secret version paths.  This function takes the sdb_id """
        sdb_resp = get_with_retry(str.join('', [self.cerberus_url, '/v1/sdb-secret-version-paths/', sdb_id]),
                                headers=self.HEADERS)

        throw_if_bad_response(sdb_resp)

        return sdb_resp.json()

    def get_sdb_secret_version_paths_by_path(self, sdb_path):
        """ Get SDB secret version paths.  This function takes the sdb_path """
        return self.get_sdb_secret_version_paths(self.get_sdb_id_by_path(sdb_path))

    def list_sdbs(self):
        """ Return sdbs by Name """
        sdb_raw = self.get_sdbs()
        sdbs = []
        for s in sdb_raw:
            sdbs.append(s['name'])

        return sdbs

    def update_sdb(self, sdb_id, owner=None, description=None, user_group_permissions=None,
                   iam_principal_permissions=None):
        """
        Update a safe deposit box.

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
        keys = ('owner', 'description', 'iam_principal_permissions', 'user_group_permissions')
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
        sdb_resp = put_with_retry(self.cerberus_url + '/v2/safe-deposit-box/' + sdb_id, data=str(data),
                                headers=self.HEADERS)

        throw_if_bad_response(sdb_resp)
        return sdb_resp.json()

###------ Files ------###
    def delete_file(self, secure_data_path):
        """Delete a file at the given secure data path"""
        secret_resp = delete_with_retry(self.cerberus_url + '/v1/secure-file/' + secure_data_path,
                                      headers=self.HEADERS)
        throw_if_bad_response(secret_resp)
        return secret_resp

    def get_file_metadata(self, secure_data_path, version=None):
        """Get just the metadata for a file, not the content"""
        if not version:
            version = "CURRENT"

        payload = {'versionId': str(version)}
        secret_resp = head_with_retry(str.join('', [self.cerberus_url, '/v1/secure-file/', secure_data_path]),
                                    params=payload, headers=self.HEADERS)

        throw_if_bad_response(secret_resp)

        return secret_resp.headers

    def _get_file(self, secure_data_path, version=None):
        """
        Return the file stored at the secure data path
        Keyword arguments:

            secure_data_path (string) -- full path in the secret deposit box that contains the key
                                   /shared/sdb-path/secret
        """
        if not version:
            version = "CURRENT"

        payload = {'versionId': str(version)}
        secret_resp = get_with_retry(str.join('', [self.cerberus_url, '/v1/secure-file/', secure_data_path]),
                                   params=payload, headers=self.HEADERS)

        throw_if_bad_response(secret_resp)

        return secret_resp

    def _parse_metadata_filename(self, metadata):
        """
        Parse the header metadata to pull out the filename and then store it under the key 'filename'
        """
        index = metadata['Content-Disposition'].index('=')+1
        metadata['filename'] = metadata['Content-Disposition'][index:].replace('"', '')
        return metadata

    def get_file(self, secure_data_path, version=None):
        """
        Return a requests.structures.CaseInsensitiveDict object containing a file and the
        metadata/header information around it.

        The binary data of the file is under the key 'data'
        """

        query = self._get_file(secure_data_path, version)
        resp = query.headers.copy()
        resp = self._parse_metadata_filename(resp)
        resp['data'] = query.content

        return resp

    def get_file_data(self, secure_data_path, version=None):
        """
        Return the data of a file stored at the secure data path
        This only returns the file data, and does not include any of the meta information stored with it.

        Keyword arguments:

            secure_data_path (string) -- full path in the secret deposit box that contains the file key
        """
        return self._get_file(secure_data_path, version).content

    def get_file_versions(self, secure_data_path, limit=None, offset=None):
        """
        Get versions of a particular file
        This is just a shim to get_secret_versions

        secure_data_path -- full path to the file in the safety deposit box
        limit -- Default(100), limits how many records to be returned from the api at once.
        offset -- Default(0), used for pagination.  Will request records from the given offset.
        """

        return self.get_secret_versions(secure_data_path, limit, offset)

    def _get_all_file_version_ids(self, secure_data_path, limit=None):
        """
        Convenience function that returns a generator that will paginate over the file version ids
        secure_data_path -- full path to the file in the safety deposit box
        limit -- Default(100), limits how many records to be returned from the api at once.
        """

        offset = 0
        # Prime the versions dictionary so that all the logic can happen in the loop
        versions = {'has_next': True, 'next_offset': 0}
        while (versions['has_next']):
            offset = versions['next_offset']
            versions = self.get_file_versions(secure_data_path, limit, offset)
            for summary in versions['secure_data_version_summaries']:
                yield summary

    def _get_all_file_versions(self, secure_data_path, limit=None):
        """
        Convenience function that returns a generator yielding the contents of all versions of
        a file and its version info

        secure_data_path -- full path to the file in the safety deposit box
        limit -- Default(100), limits how many records to be returned from the api at once.
        """
        for secret in self._get_all_file_version_ids(secure_data_path, limit):
            yield {'secret': self.get_file_data(secure_data_path, version=secret['id']),
                   'version': secret}

    def list_files(self, secure_data_path, limit=None, offset=None):
        """Return the list of files in the path.  May need to be paginated"""

        # Make sure that limit and offset are in range.
        # Set the normal defaults
        if not limit or limit <= 0:
            limit = 100

        if not offset or offset < 0:
            offset = 0

        payload = {'limit': str(limit), 'offset': str(offset)}

        # Because of the addition of versionId and the way URLs are constructed, secure_data_path should
        #  always end in a '/'.
        secure_data_path = self._add_slash(secure_data_path)
        secret_resp = get_with_retry(self.cerberus_url + '/v1/secure-files/' + secure_data_path,
                                   params=payload, headers=self.HEADERS)
        throw_if_bad_response(secret_resp)
        return secret_resp.json()

    def put_file(self, secure_data_path, filehandle, content_type=None):
        """
        Upload a file to a secure data path provided

        Keyword arguments:
        secure_data_path -- full path in the safety deposit box that contains the file key to store things under
        filehandle -- Pass an opened filehandle to the file you want to upload.
           Make sure that the file was opened in binary mode, otherwise the size calculations
           can be off for text files.
        content_type -- Optional.  Set the Mime type of the file you're uploading.
        """

        # Parse out the filename from the path
        filename = secure_data_path.rsplit('/', 1)

        if content_type:
            data = {'file-content': (filename, filehandle, content_type)}
        else:
            data = {'file-content': (filename, filehandle)}

        headers = self.HEADERS.copy()
        if 'Content-Type' in headers:
            headers.__delitem__('Content-Type')

        secret_resp = post_with_retry(self.cerberus_url + '/v1/secure-file/' + secure_data_path,
                                    files=data, headers=headers)
        throw_if_bad_response(secret_resp)
        return secret_resp

###------ Secrets -----####
    def delete_secret(self, secure_data_path):
        """Delete a secret from the given secure data path"""
        secret_resp = delete_with_retry(self.cerberus_url + '/v1/secret/' + secure_data_path,
                                      headers=self.HEADERS)
        throw_if_bad_response(secret_resp)
        return secret_resp

    def get_secret(self, secure_data_path, key, version=None):
        """
        (Deprecated)Return the secret based on the secure data path and key

        This method is deprecated because it misleads users into thinking they're only getting one value from Cerberus
        when in reality they're getting all values, from which a single value is returned.
        Use get_secrets_data(secure_data_path)[key] instead.
        (See https://github.com/Nike-Inc/cerberus-python-client/issues/18)
        """
        warnings.warn(
            "get_secret is deprecated, use get_secrets_data instead",
            DeprecationWarning
        )
        secret_resp_json = self._get_secrets(secure_data_path, version)

        if key in secret_resp_json['data']:
            return secret_resp_json['data'][key]
        else:
            raise CerberusClientException("Key '%s' not found" % key)

    def _get_secrets(self, secure_data_path, version=None):
        """
        Return full json secrets based on the secure data path
        Keyword arguments:

            secure_data_path (string) -- full path in the secret deposit box that contains the key
                                   /shared/sdb-path/secret
        """
        if not version:
            version = "CURRENT"
        payload = {'versionId': str(version)}
        secret_resp = get_with_retry(str.join('', [self.cerberus_url, '/v1/secret/', secure_data_path]),
                                   params=payload, headers=self.HEADERS)

        throw_if_bad_response(secret_resp)

        return secret_resp.json()

    def get_secrets(self, secure_data_path, version=None):
        """(Deprecated)Return json secrets based on the secure data path

        This method is deprecated because an addition step of reading value with ['data'] key from the returned
        data is required to get secrets, which contradicts the method name.
        Use get_secrets_data(secure_data_path) instead.
        (See https://github.com/Nike-Inc/cerberus-python-client/issues/19)
        """
        warnings.warn(
            "get_secrets is deprecated, use get_secrets_data instead",
            DeprecationWarning
        )
        return self._get_secrets(secure_data_path, version)

    def get_secrets_data(self, secure_data_path, version=None):
        """Return json secrets based on the secure data path

        Keyword arguments:

            secure_data_path (string) -- full path in the secret deposit box that contains the key
        """
        return self._get_secrets(secure_data_path, version)['data']

    def get_secret_versions(self, secure_data_path, limit=None, offset=None):
        """
        Get versions of a particular secret key

        secure_data_path -- full path to the key in the safety deposit box
        limit -- Default(100), limits how many records to be returned from the api at once.
        offset -- Default(0), used for pagination.  Will request records from the given offset.
        """

        # Make sure that limit and offset are in range.
        # Set the normal defaults
        if not limit or limit <= 0:
            limit = 100

        if not offset or offset < 0:
            offset = 0

        payload = {'limit': str(limit), 'offset': str(offset)}
        secret_resp = get_with_retry(str.join('', [self.cerberus_url, '/v1/secret-versions/', secure_data_path]),
                                   params=payload, headers=self.HEADERS)
        throw_if_bad_response(secret_resp)
        return secret_resp.json()

    def _get_all_secret_version_ids(self, secure_data_path, limit=None):
        """
        Convenience function that returns a generator that will paginate over the secret version ids
        secure_data_path -- full path to the key in the safety deposit box
        limit -- Default(100), limits how many records to be returned from the api at once.
        """

        offset = 0
        # Prime the versions dictionary so that all the logic can happen in the loop
        versions = {'has_next': True, 'next_offset': 0}
        while (versions['has_next']):
            offset = versions['next_offset']
            versions = self.get_secret_versions(secure_data_path, limit, offset)
            for summary in versions['secure_data_version_summaries']:
                yield summary

    def _get_all_secret_versions(self, secure_data_path, limit=None):
        """
        Convenience function that returns a generator yielding the contents of secrets and their version info
        secure_data_path -- full path to the key in the safety deposit box
        limit -- Default(100), limits how many records to be returned from the api at once.
        """
        for secret in self._get_all_secret_version_ids(secure_data_path, limit):
            yield {'secret': self.get_secrets_data(secure_data_path, version=secret['id']),
                   'version': secret}

    def list_secrets(self, secure_data_path):
        """Return json secrets based on the secure_data_path, this will list keys in a folder"""

        # Because of the addition of versionId and the way URLs are constructed, secure_data_path should
        #  always end in a '/'.
        secure_data_path = self._add_slash(secure_data_path)
        secret_resp = get_with_retry(self.cerberus_url + '/v1/secret/' + secure_data_path + '?list=true',
                                   headers=self.HEADERS)
        throw_if_bad_response(secret_resp)
        return secret_resp.json()

    def put_secret(self, secure_data_path, secret, merge=True):
        """Write secret(s) to a secure data path provided a dictionary of key/values

        Keyword arguments:
        secure_data_path -- full path in the safety deposit box that contains the key
        secret -- A dictionary containing key/values to be written at the secure data path
        merge -- Boolean that determines if the provided secret keys should be merged with
            the values already present at the secure data path.  If False the keys will
            completely overwrite what was stored at the secure data path. (default True)
        """
        # json encode the input.  Cerberus is sensitive to double vs single quotes.
        # an added bonus is that json encoding transforms python2 unicode strings
        # into a compatible format.
        data = json.encoder.JSONEncoder().encode(secret)
        if merge:
            data = self.secret_merge(secure_data_path, secret)
        secret_resp = post_with_retry(self.cerberus_url + '/v1/secret/' + secure_data_path,
                                    data=str(data), headers=self.HEADERS)
        throw_if_bad_response(secret_resp)
        return secret_resp

    def secret_merge(self, secure_data_path, key):
        """Compare key/values at secure_data_path and merges them.  New values will overwrite old."""
        get_resp = get_with_retry(self.cerberus_url + '/v1/secret/' + secure_data_path, headers=self.HEADERS)
        temp_key = {}
        # Ignore a return of 404 since it means the key might not exist
        if get_resp.status_code == requests.codes.bad and get_resp.status_code not in [403, 404]:
            throw_if_bad_response(get_resp)
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
