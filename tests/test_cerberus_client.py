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
import unittest

import requests
from mock import patch
from nose.tools import assert_equals, assert_in

from cerberus import CerberusClientException
from cerberus.client import CerberusClient


class TestCerberusClient(unittest.TestCase):
    """Class to test the cerberus client. Mock is used to mock external calls"""
    @patch('cerberus.client.CerberusClient.set_token', return_value='1234-asdf-1234hy-qwer6')
    def setUp(self, *args):
        self.cerberus_url = "https://cerberus.fake.com"
        self.client = CerberusClient(
            self.cerberus_url,
            'testuser', 'hardtoguesspasswd'
        )
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
    def _mock_response(status=200, reason='OK', content=''):
        mock_resp = requests.Response()
        mock_resp.status_code = status
        # Reason the status code occurred.
        mock_resp.reason = reason
        # Raw content in byte
        mock_resp._content = bytes(content.encode('utf-8'))
        return mock_resp

    def test_username(self):
        """ Testing that correct username is returned"""
        assert_equals(self.client.username, 'testuser')

    def test_get_token(self):
        """ Testing that get_token returns the correct token"""
        token = self.client.get_token()
        assert_equals(token, self.client.token)

    @patch('requests.get')
    def test_get_sdb_id(self, mock_get):
        """ Testing that get_sdb_id returns the correct ID"""
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
        assert_in('X-Cerberus-Client', self.client.HEADERS)
        mock_get.assert_called_with(
            self.cerberus_url + '/v1/safe-deposit-box',
            headers=self.client.HEADERS
        )

    @patch('cerberus.client.CerberusClient.get_sdb_id', return_value="5f0-99-414-bc-e5909c")
    @patch('requests.get')
    def test_get_sdb_path(self, mock_get, mock_sdb_id):
        """ Test that get_sdb_path returns the correct path """
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
        assert_in('X-Cerberus-Client', self.client.HEADERS)
        mock_get.assert_called_with(
            self.cerberus_url + '/v1/safe-deposit-box/5f0-99-414-bc-e5909c/',
            headers=self.client.HEADERS
        )

    @patch('requests.get')
    def test_get_sdb_keys(self, mock_get):
        """ Testing that get_sdb_keys returns the correct key """
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
        assert_in('X-Cerberus-Client', self.client.HEADERS)
        mock_get.assert_called_with(
            self.cerberus_url + '/v1/secret/fake/path/?list=true',
            headers=self.client.HEADERS
        )

    @patch('requests.get')
    def test_getting_a_secret(self, mock_get):
        """ Testing the correct secret is returned"""
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
        assert_in('X-Cerberus-Client', self.client.HEADERS)
        mock_get.assert_called_with(
            self.cerberus_url + '/v1/secret/fake/path',
            headers=self.client.HEADERS
        )

    @patch('requests.get')
    def test_get_secrets_invalid_path(self, mget):
        """ Ensure that a Cerberus exception is raised if the path is invalid. """
        mget.return_value = self._mock_response(status=401)
        with self.assertRaises(CerberusClientException):
            self.client.get_secrets('this/path/does/not/exist')

    @patch('requests.get')
    def test_get_secret_invalid_path(self, mget):
        """ Ensure that a Cerberus exception is raised if the path or key is invalid. """
        data = json.dumps({"data": {}})
        mget.return_value = self._mock_response(content=data)
        with self.assertRaises(CerberusClientException):
            self.client.get_secret('this/path/does/not/exist', 'null')

    @patch('requests.get')
    def test_get_sdb_id_invalid_response(self, mget):
        """ Ensure a Cerberus exception is raised if the sdb request failed. """
        mget.return_value = self._mock_response(status=401)
        with self.assertRaises(CerberusClientException):
            self.client.get_sdb_id('some_id')

    @patch('requests.get')
    def test_get_sdb_id_missing_id(self, mget):
        """ Ensure a Cerberus exception is raised if the sdb id is not found. """
        data = [
            {
                "id": "5f0-99-414-bc-e5909c",
                "name": "Disco Events",
                "path": "app/disco-events/",
                "category_id": "b07-42d0-e6-9-0a47c03"
            }
        ]
        mget.return_value = self._mock_response(content=json.dumps(data))
        with self.assertRaises(CerberusClientException):
            self.client.get_sdb_id('not_found')
