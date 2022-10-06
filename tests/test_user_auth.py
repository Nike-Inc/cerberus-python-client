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

# Stuff for tests...
import json
import sys

import requests
from cerberus import CerberusClientException
from mock import patch
from mock import call
from nose.tools import raises, assert_equals, assert_dict_equal

from cerberus.user_auth import UserAuth


class TestUserAuth(object):
    """Test class fo user auth. This uses Mock to mock external API calls"""

    @classmethod
    def setup_class(cls):
        """ set-up class """
        cls.client = UserAuth("https://cerberus.fake.com", 'testuser', 'hardtoguesspasswd')
        cls.mfa_data = {
            "status": "success",
            "data": {
                "user_id": "134",
                "username": "unicorn@rainbow.com",
                "state_token": None,
                "devices": [],
                "client_token": {
                    "client_token": "61e3-f3f-6536-a3e6-b498161d",
                    "policies": ["cloud-events-owner", "pixie-dust-owner"],
                    "metadata": {
                        "groups": "Rainbow.Playgroun.User,CareBear.users",
                        "is_admin": "false",
                        "username": "unicorn@rainbow.com"
                    },
                    "lease_duration": 3600,
                    "renewable": True
                }
            }
        }
        cls.auth_resp = {
            "status": "mfa_req",
            "data": {
                "username": "unicorn@rainbow.com",
                "state_token": "0127a384d305138d4e",
                "client_token": "None",
                "user_id": "1325",
                "devices": [{"id": "223", "name": "Google Authenticator"}]
            }
        }
        cls.auth_resp_multi = {
            "status": "mfa_req",
            "data": {
                "username": "unicorn@rainbow.com",
                "state_token": "0127a384d305138d4e",
                "client_token": "None",
                "user_id": "1325",
                "devices": [
                  {"id": "223", "name": "Google Authenticator"},
                  {"id": "224", "name": "OTP Authenticator"},
                  {"id": "225", "name": "Okta Text Message Code", "requires_trigger": True}
                  ]
            }
        }

    @staticmethod
    def _mock_response(status=200, reason=None, content=''):
        mock_resp = requests.Response()
        mock_resp.status_code = status
        # Reason the status code occurred.
        mock_resp.reason = reason
        # Raw content in byte
        mock_resp._content = bytes(content.encode('utf-8'))
        return mock_resp

    def test_username(self):
        """ Testing to make sure username match """
        assert_equals(self.client.username, 'testuser')

    @patch('cerberus.user_auth.UserAuth.get_auth')
    def test_get_token(self, mock_get_auth):
        """ Test to make sure the correct token is returned """
        mock_get_auth.return_value = {
            "status": "success",
            "data": {
                "client_token": {
                    "client_token": "7f6808f1-ede3-2177-aa9d-45f507391310",
                }
            }
        }
        token = self.client.get_token()
        assert_equals(token, '7f6808f1-ede3-2177-aa9d-45f507391310')

    @patch('requests.get')
    def test_get_auth(self, mock_get):
        """" Test that correct response is returned by get_auth """
        # mock return response
        mock_resp = self._mock_response(content=json.dumps(self.auth_resp))
        mock_get.return_value = mock_resp
        response = self.client.get_auth()

        # confirm response matches the mock
        assert_dict_equal(response, self.auth_resp)

    if sys.version_info[0] < 3:
        input_module = '__builtin__.input'
    else:
        input_module = 'builtins.input'

    @patch('cerberus.user_auth.UserAuth.get_mfa')
    @patch('cerberus.user_auth.UserAuth.get_auth')
    def test_get_token_mfa_req(self, mock_get_auth, mock_get_mfa, mock_input=None):
        """ Test to make sure the correct token is returned """
        mock_get_auth.return_value = self.auth_resp
        mock_get_mfa.return_value = {
            "status": "success",
            "data": {
                "client_token": {
                    "client_token": "7f6808f1-ede3-2177-aa9d-45f507391310",
                }
            }
        }
        token = self.client.get_token()
        assert_equals(token, '7f6808f1-ede3-2177-aa9d-45f507391310')


    @patch(input_module, return_value='0987654321')
    @patch('requests.post')
    def test_mfa_response(self, mock_post, mock_input=None):
        """ Testing that mfa_response returns the correct json """
        # mock all the things
        mock_post.return_value = self._mock_response(content=json.dumps(self.mfa_data))

        response = self.client.get_mfa(self.auth_resp)

        # confirm the json matches
        assert_dict_equal(response, self.mfa_data)

    @patch(input_module, side_effect=[ '1', '0987654321'])
    @patch('requests.post')
    def test_multi_mfa_response(self, mock_post, mock_input=None):
        """ Testing that mfa_response returns the correct json when there are multiple MFAs available """
        # mock all the things
        mock_post.return_value = self._mock_response(content=json.dumps(self.mfa_data))

        response = self.client.get_mfa(self.auth_resp_multi)

        # confirm the json matches
        assert_dict_equal(response, self.mfa_data)

    @patch(input_module, side_effect=[ '2', '0987654321'])
    @patch('requests.post')
    def test_multi_mfa_response_sms(self, mock_post, mock_input=None):
        """ Testing Text flow to make sure it triggers the sending of the SMS message"""
        mock_post.return_value = self._mock_response(content=json.dumps(self.mfa_data))

        response = self.client.get_mfa(self.auth_resp_multi)
        trigger_call = call('https://cerberus.fake.com/v2/auth/mfa_check',
                            json={'device_id': '225',
                                  'state_token': '0127a384d305138d4e'},
                            headers={'Content-Type': 'application/json',
                                     'X-Cerberus-Client': 'CerberusPythonClient/2.5.4'})

        check_call = call('https://cerberus.fake.com/v2/auth/mfa_check',
                          json={'otp_token': '0987654321',
                                'device_id': '225', 'state_token': '0127a384d305138d4e'},
                          headers={'Content-Type': 'application/json',
                                   'X-Cerberus-Client': 'CerberusPythonClient/2.5.4'})

        expected_calls = [trigger_call, check_call]

        assert_equals(mock_post.mock_calls, expected_calls)

        assert_dict_equal(response, self.mfa_data)


    @raises(CerberusClientException)
    @patch(input_module, return_value='a1')
    def test_multi_mfa_response_text(self, mock_input=None):
        """ Testing improper inputs for Multiple MFA selections, (a1) """
        # mock all the things
        response = self.client.get_mfa(self.auth_resp_multi)

    @raises(CerberusClientException)
    @patch(input_module, return_value='-1')
    def test_multi_mfa_response_low(self, mock_input=None):
        """ Testing improper inputs for Multiple MFA selections, (-1) """
        # mock all the things
        response = self.client.get_mfa(self.auth_resp_multi)

    @raises(CerberusClientException)
    @patch(input_module, return_value='3')
    def test_multi_mfa_response_high(self, mock_input=None):
        """ Testing improper inputs for Multiple MFA selections, (3) """
        # mock all the things
        response = self.client.get_mfa(self.auth_resp_multi)

    @raises(CerberusClientException)
    @patch('requests.get')
    def test_when_not_200_status_code(self, mock_get):
        """ test when 200 status code is not returned"""
        data = json.dumps({"error_id": "123", "errors": []})
        mock_resp = self._mock_response(status=404, reason='Not Found', content=data)
        mock_get.return_value = mock_resp
        self.client.get_auth()
