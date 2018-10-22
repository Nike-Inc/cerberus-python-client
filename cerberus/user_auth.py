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
from . import CerberusClientException, CLIENT_VERSION

from .util import throw_if_bad_response, get_with_retry, post_with_retry


class UserAuth(object):
    """Class to authenticate with username and password and returns a cerberus token"""
    HEADERS = {"Content-Type": "application/json", "X-Cerberus-Client": "CerberusPythonClient/" + CLIENT_VERSION}

    def __init__(self, cerberus_url, username, password):
        self.cerberus_url = cerberus_url
        self.username = username
        self.password = password


    def get_auth(self):
        """Returns auth response which has client token unless MFA is required"""
        auth_resp = get_with_retry(self.cerberus_url + '/v2/auth/user',
                                 auth=(self.username, self.password),
                                 headers=self.HEADERS)

        if auth_resp.status_code != 200:
            throw_if_bad_response(auth_resp)

        return auth_resp.json()

    def get_token(self):
        """sets client token from Cerberus"""
        auth_resp = self.get_auth()

        if auth_resp['status'] == 'mfa_req':
            token_resp = self.get_mfa(auth_resp)
        else:
            token_resp = auth_resp

        token = token_resp['data']['client_token']['client_token']
        return token

    def get_mfa(self, auth_resp):
        """Gets MFA code from user and returns response which includes the client token"""
        devices = auth_resp['data']['devices']
        if len(devices) == 1:
            # If there's only one option, don't show selection prompt
            selection = "0"
            x = 1
        else:
            print("Found the following MFA devices")
            x=0
            for device in devices:
                print("{0}: {1}".format(x, device['name']))
                x = x + 1

            selection = input("Enter a selection: ")
        if selection.isdigit():
            selection_num=int(str(selection))
        else:
            raise CerberusClientException( str.join('', ["Selection: '", selection,"' is not a number"]))

        if (selection_num >= x) or (selection_num < 0):
            raise CerberusClientException(str.join('', ["Selection: '", str(selection_num), "' is out of range"]))

        sec_code = input('Enter ' + auth_resp['data']['devices'][selection_num]['name'] + ' security code: ')

        mfa_resp = post_with_retry(
            self.cerberus_url + '/v2/auth/mfa_check',
            json={'otp_token': sec_code,
                  'device_id': auth_resp['data']['devices'][selection_num]['id'],
                  'state_token': auth_resp['data']['state_token']},
            headers=self.HEADERS
        )

        if mfa_resp.status_code != 200:
            throw_if_bad_response(mfa_resp)

        return mfa_resp.json()
