"""
Copyright 2016-present Nike, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
You may not use this file except in compliance with the License.
You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and*
limitations under the License.*
"""

import logging

from . import CerberusClientException, CLIENT_VERSION

from .network_util import throw_if_bad_response
from .network_util import get_with_retry
from .network_util import post_with_retry


logger = logging.getLogger(__name__)


class UserAuth:
    """Class to authenticate with username and
       password and returns a cerberus token"""
    HEADERS = {"Content-Type": "application/json",
               "X-Cerberus-Client": "CerberusPythonClient/" + CLIENT_VERSION}

    def __init__(self, cerberus_url, username, password):
        self.cerberus_url = cerberus_url
        self.username = username
        self.password = password

    def get_auth(self):
        """Returns auth response which has client
           token unless MFA is required"""
        auth_resp = get_with_retry(self.cerberus_url + '/v2/auth/user',
                                   auth=(self.username, self.password),
                                   headers=self.HEADERS)

        self.check_response(auth_resp)

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

    @classmethod
    def check_response(cls, response):
        """Ensure a reponse has a 200 status code"""
        if response.status_code != 200:
            throw_if_bad_response(response)

    def mfa_check(self, json_param):
        """Posts json_param to mfa_check endpoint and returns the result
           after checking the status with check_response"""

        mfa_resp = post_with_retry(
            self.cerberus_url + '/v2/auth/mfa_check',
            json=json_param,
            headers=self.HEADERS
        )

        self.check_response(mfa_resp)
        return mfa_resp

    def trigger_challenge(self, device_id, state_token):
        """Trigger a challenge for devices that need them"""

        self.mfa_check({'device_id': device_id,
                        'state_token': state_token})

    def check_mfa_code(self, sec_code, device_id, state_token):
        """Check the otp token for a device"""

        mfa_resp = self.mfa_check({'otp_token': sec_code,
                                   'device_id': device_id,
                                   'state_token': state_token})
        return mfa_resp.json()

    @classmethod
    def get_valid_device_selection(cls, devices):
        """Display a list of the user's devices and get their selection"""

        if len(devices) == 1:
            # If there's only one option, don't show selection prompt
            return 0

        print("Found the following MFA devices")
        for index, device in enumerate(devices):
            print("%s: %s" % (index, device['name']))

        selection = input("Enter a selection: ")

        if selection.isdigit():
            selection_num = int(str(selection))
        else:
            msg = "Selection: '%s' is not a number" % selection
            raise CerberusClientException(msg)

        if selection_num not in range(len(devices)):
            msg = "Selection: '%s' is out of range" % selection_num
            raise CerberusClientException(msg)

        return selection_num

    def get_mfa(self, auth_resp):
        """Gets MFA code from user and returns response which
           includes the client token"""
        devices = auth_resp['data']['devices']
        selection_num = self.get_valid_device_selection(devices)

        selected_device = auth_resp['data']['devices'][selection_num]
        device_id = selected_device['id']
        state_token = auth_resp['data']['state_token']

        if selected_device.get('requires_trigger'):
            self.trigger_challenge(device_id, state_token)

        sec_code = input('Enter %s security code: ' % selected_device['name'])

        return self.check_mfa_code(sec_code, device_id, state_token)
