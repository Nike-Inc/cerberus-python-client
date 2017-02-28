# Stuff for tests...
import json
import sys

import requests
from mock import patch
from nose.tools import raises, assert_equals, assert_dict_equal
from requests.exceptions import HTTPError

from cerberus.user_auth import UserAuth


class TestUserAuth(object):
    """Test class fo user auth. This uses Mock to mock external API calls"""
    @classmethod
    def setup_class(cls):
        cls.client = UserAuth("https://cerberus.fake.com", 'testuser', 'hardtoguesspasswd')
        cls.auth_resp = {
            "status": "mfa_req",
            "data": {
                "username": "unicorn@rainbow.com",
                "state_token": "0127a384d305138d4e",
                "client_token": "None", "user_id": "1325",
                "devices": [{"id": "223", "name": "Google Authenticator"}]
            }
        }

    @staticmethod
    def _mock_response(status=200, reason=None, content=None):
        mock_resp = requests.Response()
        mock_resp.status_code = status
        # Reason the status code occurred.
        mock_resp.reason = reason
        # Raw content in byte
        mock_resp._content = bytes(content)
        return mock_resp

    def test_username(self):
        assert_equals(self.client.username, 'testuser')

    @patch('cerberus.user_auth.UserAuth.get_auth')
    def test_get_token(self, mock_get_auth):
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

    @patch(input_module, return_value='0987654321')
    @patch('requests.post')
    def test_mfa_response(self, mock_post, mock_input=None):
        mfa_data = {
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

        # mock all the things
        mock_post.return_value = self._mock_response(content=json.dumps(mfa_data))

        response = self.client.get_mfa(self.auth_resp)

        # confirm the json matches
        assert_dict_equal(response, mfa_data)

    @raises(HTTPError)
    @patch('requests.get')
    def test_when_not_200_status_code(self, mock_get):
        mock_resp = self._mock_response(status=404, reason='Not Found')
        mock_get.return_value = mock_resp
        self.client.get_auth()
