# Stuff for tests...
import json
import unittest

import requests
from mock import patch
from nose.tools import assert_equals

from cerberus.client import CerberusClient


class TestCerberusClient(unittest.TestCase):
    """Class to test the cerberus client. Mock is used to mock external calls"""
    @patch('cerberus.client.CerberusClient.set_token', return_value='1234-asdf-1234hy-qwer6')
    def setUp(self, *args):
        self.client = CerberusClient("https://cerberus.fake.com", 'testuser', 'hardtoguesspasswd' )
        self.auth_resp = {
            "status": "mfa_req",
            "data": {
                "username": "unicorn@rainbow.com",
                "state_token": "0127a384d305138d4e",
                "client_token": "None", "user_id": "1325",
                "devices": [{"id": "223", "name": "Google Authenticator"}]
            }
        }

    @staticmethod
    def _mock_response(status=200, reason='OK', content=None):
        mock_resp = requests.Response()
        mock_resp.status_code = status
        # Reason the status code occurred.
        mock_resp.reason = reason
        # Raw content in byte
        mock_resp._content = bytes(content)
        return mock_resp

    def test_username(self):
        assert_equals(self.client.username, 'testuser')

    def test_get_token(self):
        token = self.client.get_token()
        assert_equals(token, self.client.token)

    @patch('requests.get')
    def test_get_sdb_id(self, mock_get):
        sdb_data = [
            {
                "id": "5f0-99-414-bc-e5909c",
                "name": "Disco Events",
                "path": "app/disco-events/",
                "category_id": "b07-42d0-e6-9-0a47c03"
            },
            {
                "id": "a7192aa7-83f0-45b7-91fb-f6b0eb",
                "name": "snowflake",
                "path": "app/snowflake/",
                "category_id": "b042d0-e6-90-0aec03"
            }
        ]

        mock_get.return_value = self._mock_response(content=json.dumps(sdb_data))
        sdb_id = self.client.get_sdb_id("snowflake")

        # confirm the id matches
        assert_equals(sdb_id, sdb_data[1]['id'])

    @patch('cerberus.client.CerberusClient.get_sdb_id', return_value="5f0-99-414-bc-e5909c")
    @patch('requests.get')
    def test_get_sdb_path(self, mock_get, mock_sdb_id):
        sdb_data = {
            "id": "5f0-99-414-bc-e5909c",
            "name": "Disco Events",
            "description": "Studio 54",
            "path": "app/disco-events/"
        }

        mock_resp = self._mock_response(content=json.dumps(sdb_data))
        mock_get.return_value = mock_resp

        path = self.client.get_sdb_path("Disco Events")

        assert_equals(path, sdb_data['path'])

    @patch('requests.get')
    def test_get_sdb_keys(self, mock_get):
        list_data = {
            "lease_id": "",
            "renewable": False,
            "lease_duration": 0,
            "data": {"keys": ["magic", "princess"]},
            "wrap_info": None,
            "warnings": None,
            "auth": None
        }

        mock_resp = self._mock_response(content=json.dumps(list_data))
        mock_get.return_value = mock_resp

        keys = self.client.get_sdb_keys('fake/path')

        assert_equals(keys[0], 'magic')
        assert_equals(keys[1], 'princess')

    @patch('requests.get')
    def test_getting_a_secret(self, mock_get):
        secret_data = {
            "data": {
                "mykey": "mysecretdata",
                "myotherkey": "moretopsecretstuff"
            }
        }

        mock_resp = self._mock_response(content=json.dumps(secret_data))
        mock_get.return_value = mock_resp

        secret = self.client.get_secret('fake/path', 'myotherkey')

        # check to make sure we got the right secret
        assert_equals(secret, 'moretopsecretstuff')
