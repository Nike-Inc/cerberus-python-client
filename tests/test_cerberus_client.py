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
import ast
import json
import unittest

import requests
import mock
from mock import patch, ANY
from nose.tools import assert_equals, assert_in
from .matcher import AnyDictWithKey

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
        self.sdb_data = {
            "id": "5f0-99-414-bc-e5909c",
            "name": "Disco Events",
            "description": "Studio 54",
            "path": "app/disco-events/",
            'iam_principal_permissions':
                [{'created_by': 'tester@studio54.com',
                    'iam_principal_arn': 'arn:aws:iam::292800423415:role/studio54-dancefloor',
                    'id': 'c8549195-5f2c-ba2c-eb0e-2605d1e58816',
                    'last_updated_by': 'tester@studio54.com',
                    'last_updated_ts': '1974-11-17T00:02:30Z',
                    'role_id': '8609a0c3-31e5-49ab-914d-c70c35da9478'},
                {'created_by': 'tester@studio54.com',
                    'iam_principal_arn': 'arn:aws:iam::292800423415:role/studio54-bar',
                    'id': 'f57741a2-79c0-7e35-bbf9-82a32a1827eb',
                    'last_updated_by': 'tester@studio54.com',
                    'last_updated_ts': '1974-11-17T00:02:30Z',
                    'role_id': '8609a0c3-31e5-49ab-914d-c70c35da9478'},
                {'created_by': 'tester@studio54.com',
                    'iam_principal_arn': 'arn:aws:iam::292800423415:role/studio54-office',
                    'id': '27731199-7055-3c4b-3883-9f01f17bc034',
                    'last_updated_by': 'tester@studio54.com',
                    'last_updated_ts': '1974-11-17T00:02:30Z',
                    'role_id': '8609a0c3-31e5-49ab-914d-c70c35da9478'}],
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

    @staticmethod
    def _mock_response_raw(status=200, reason='OK', content=''):
        mock_resp = requests.Response()
        mock_resp.status_code = status
        # Reason the status code occurred.
        mock_resp.reason = reason
        mock_resp._content = bytes(content.encode('utf-8'))
        return mock_resp.json()

    def test_username(self):
        """ Testing that correct username is returned"""
        assert_equals(self.client.username, 'testuser')

    def test_get_token(self):
        """ Testing that get_token returns the correct token"""
        token = self.client.get_token()
        assert_equals(token, self.client.token)

    @patch('requests.get')
    def test_get_sdbs(self, mock_get):
        """ get_sdbs: Testing that get_sdbs returns the correct SDBs """
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
        sdb_id = self.client.get_sdbs()

        assert_in('X-Cerberus-Client', self.client.HEADERS)
        mock_get.assert_called_with(
            self.cerberus_url + '/v2/safe-deposit-box',
            headers=self.client.HEADERS
        )


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

    @patch('requests.get')
    def test_list_sdbs(self, mock_get):
        """ list_sdbs: Testing that list_sdbs returns the correct SDBs names """
        sdb_data = [
            {
                "name": "Disco Events"
            },
            {
                "name": "snowflake"
            }
        ]

        mock_get.return_value = self._mock_response(content=json.dumps(sdb_data))
        sdb_id = self.client.list_sdbs()

        assert_in('X-Cerberus-Client', self.client.HEADERS)
        mock_get.assert_called_with(
            self.cerberus_url + '/v2/safe-deposit-box',
            headers=self.client.HEADERS
        )


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
            self.cerberus_url + '/v2/safe-deposit-box',
            headers=self.client.HEADERS
        )

    @patch('requests.get')
    def test_get_sdb_id_by_path(self, mock_get):
        """ Testing that get_sdb_id_by_path returns the correct ID"""
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
        sdb_id = self.client.get_sdb_id_by_path("app/snowflake/")

        # confirm the id matches
        assert_equals(sdb_id, sdb_data[1]['id'])
        assert_in('X-Cerberus-Client', self.client.HEADERS)
        mock_get.assert_called_with(
            self.cerberus_url + '/v2/safe-deposit-box',
            headers=self.client.HEADERS
        )

    @patch('requests.get')
    def test_get_sdb_id_by_path_no_slash(self, mock_get):
        """
        Testing that get_sdb_id_by_path returns the correct ID \
        even when the requested path lacks a trailing slash '/'
        """
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
        sdb_id = self.client.get_sdb_id_by_path("app/snowflake")

        # confirm the id matches
        assert_equals(sdb_id, sdb_data[1]['id'])
        assert_in('X-Cerberus-Client', self.client.HEADERS)
        mock_get.assert_called_with(
            self.cerberus_url + '/v2/safe-deposit-box',
            headers=self.client.HEADERS
        )

    @patch('cerberus.client.CerberusClient.get_sdb_id', return_value="5f0-99-414-bc-e5909c")
    @patch('requests.get')
    def test_get_sdb_by_id(self, mock_get, mock_sdb_id):
        """ Test that get_sdb_by_id returns some details of the sdb """

        mock_resp = self._mock_response(content=json.dumps(self.sdb_data))
        mock_get.return_value = mock_resp

        details = self.client.get_sdb_by_id("5f0-99-414-bc-e5909c")

        assert_equals(details, self.sdb_data)
        assert_in('X-Cerberus-Client', self.client.HEADERS)
        mock_get.assert_called_with(
            self.cerberus_url + '/v2/safe-deposit-box/5f0-99-414-bc-e5909c',
            headers=self.client.HEADERS
        )

    @patch('cerberus.client.CerberusClient.get_sdb_id', return_value="5f0-99-414-bc-e5909c")
    @patch('requests.get')
    def test_get_sdb_by_name(self, mock_get, mock_sdb_id):
        """ Test that get_sdb_by_name returns some details of the sdb """

        mock_resp = self._mock_response(content=json.dumps(self.sdb_data))
        mock_get.return_value = mock_resp

        details = self.client.get_sdb_by_name("Disco Events")

        assert_equals(details, self.sdb_data)
        assert_in('X-Cerberus-Client', self.client.HEADERS)
        mock_get.assert_called_with(
            self.cerberus_url + '/v2/safe-deposit-box/5f0-99-414-bc-e5909c',
            headers=self.client.HEADERS
        )

    @patch('cerberus.client.CerberusClient.get_sdb_id_by_path', return_value="5f0-99-414-bc-e5909c")
    @patch('requests.get')
    def test_get_sdb_by_path(self, mock_get, mock_sdb_id):
        """ Test that get_sdb_by_path returns some details of the sdb """

        mock_resp = self._mock_response(content=json.dumps(self.sdb_data))
        mock_get.return_value = mock_resp

        details = self.client.get_sdb_by_path("app/disco-events/")

        assert_equals(details, self.sdb_data)
        assert_in('X-Cerberus-Client', self.client.HEADERS)
        mock_get.assert_called_with(
            self.cerberus_url + '/v2/safe-deposit-box/5f0-99-414-bc-e5909c',
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

    @patch('requests.post')
    def test_create_sdb(self, mock_get):
        """ Test creation of sdb """
        sdb_data = {
            'id': '5f0-99-414-bc-e5909c',
            'name': 'Disco Events',
            'description': 'Studio 54',
            'path': 'app/disco-events/',
            'category_id': '244cfc0d-4beb-8189-5056-194f18ead6f4',
            'created_by': 'tester@studio54.com',
            'created_ts': '1978-11-27T23:08:14.027Z',
            'iam_principal_permissions': [{
                'created_by': 'tester@studio54.com',
                'iam_principal_arn': 'arn:aws:iam::292800423415:role/studio54-dancefloor',
                'id': 'c8549195-5f2c-ba2c-eb0e-2605d1e58816',
                'last_updated_by': 'tester@studio54.com',
                'last_updated_ts': '1974-11-17T00:02:30Z',
                'role_id': '8609a0c3-31e5-49ab-914d-c70c35da9478'},
                {'created_by': 'tester@studio54.com',
                 'iam_principal_arn': 'arn:aws:iam::292800423415:role/studio54-bar',
                 'id': 'f57741a2-79c0-7e35-bbf9-82a32a1827eb',
                 'last_updated_by': 'tester@studio54.com',
                 'last_updated_ts': '1974-11-17T00:02:30Z',
                 'role_id': '8609a0c3-31e5-49ab-914d-c70c35da9478'},
                {'created_by': 'tester@studio54.com',
                 'iam_principal_arn': 'arn:aws:iam::292800423415:role/studio54-office',
                 'id': '27731199-7055-3c4b-3883-9f01f17bc034',
                 'last_updated_by': 'tester@studio54.com',
                 'last_updated_ts': '1974-11-17T00:02:30Z',
                 'role_id': '8609a0c3-31e5-49ab-914d-c70c35da9478'}],
            'owner': 'Admin.Studio.54',
            'user_group_permissions': []
            }
        mock_resp = mock.Mock()
        mock_resp.json.return_value = sdb_data
        #mock_resp = self._mock_response(content=json.dumps(sdb_data))
        mock_get.return_value = mock_resp

        create = self.client.create_sdb(
            'Disco Events',
            '244cfc0d-4beb-8189-5056-194f18ead6f4',
            'Admin.Studio.54',
            'Studio 54',
            [],
            [
                {
                    'iam_principal_arn': 'arn:aws:iam::292800423415:role/studio54-dancefloor',
                    'role_id': '8609a0c3-31e5-49ab-914d-c70c35da9478'
                },
                {
                    'iam_principal_arn': 'arn:aws:iam::292800423415:role/studio54-bar',
                    'role_id': '8609a0c3-31e5-49ab-914d-c70c35da9478'
                },
                {
                    'iam_principal_arn': 'arn:aws:iam::292800423415:role/studio54-office',
                    'role_id': '8609a0c3-31e5-49ab-914d-c70c35da9478'
                },
            ]
            )

        assert_equals(create, sdb_data)
        assert_in('X-Cerberus-Client', self.client.HEADERS)
        #mock_get.assert_called_once_with(self.cerberus_url + '/v2/safe-deposit-box')
        #mock_get.assert_called_with(
        #    self.cerberus_url + '/v2/safe-deposit-box',
        #    data={"owner": "Admin.Studio.54", "iam_principal_permissions": [{"iam_principal_arn": "arn:aws:iam::292800423415:role/studio54-dancefloor", "role_id": "8609a0c3-31e5-49ab-914d-c70c35da9478"}, {"iam_principal_arn": "arn:aws:iam::292800423415:role/studio54-bar", "role_id": "8609a0c3-31e5-49ab-914d-c70c35da9478"}, {"iam_principal_arn": "arn:aws:iam::292800423415:role/studio54-office", "role_id": "8609a0c3-31e5-49ab-914d-c70c35da9478"}], "description": "Studio 54", "category_id": "244cfc0d-4beb-8189-5056-194f18ead6f4", "name": "Disco Events"},
        #    headers=self.client.HEADERS
        #)

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
        """ get_secret: Testing the correct secret is returned"""
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
            params={'versionId': 'CURRENT'}, headers=self.client.HEADERS
        )

    @patch('requests.get')
    def test_getting_secrets_data(self, mock_get):
        """ get_secrets_data: Testing the correct secrets are returned"""
        secret_data = {
            "data": {
                "sushi": "ikenohana",
                "ramen": "yuzu"
            }
        }

        mock_resp = self._mock_response(content=json.dumps(secret_data))
        mock_get.return_value = mock_resp

        secrets = self.client.get_secrets_data('fake/path')

        # check to make sure we got the right secret
        assert_equals(secrets['sushi'], 'ikenohana')
        assert_equals(secrets['ramen'], 'yuzu')
        assert_in('X-Cerberus-Client', self.client.HEADERS)
        mock_get.assert_called_with(
            self.cerberus_url + '/v1/secret/fake/path',
            params={'versionId': 'CURRENT'}, headers=self.client.HEADERS
        )

    @patch('requests.get')
    def test_getting_secrets_data_version(self, mock_get):
        """ get_secrets_data: Testing the correct secrets are returned when a version is passed """
        secret_data = {
            "data": {
                "sushi": "ikenohana",
                "ramen": "yuzu"
            }
        }

        mock_resp = self._mock_response(content=json.dumps(secret_data))
        mock_get.return_value = mock_resp

        secrets = self.client.get_secrets_data('fake/path', version='12345')

        # check to make sure we got the right secret
        assert_equals(secrets['sushi'], 'ikenohana')
        assert_equals(secrets['ramen'], 'yuzu')
        assert_in('X-Cerberus-Client', self.client.HEADERS)
        mock_get.assert_called_with(
            self.cerberus_url + '/v1/secret/fake/path',
            params={'versionId': '12345'}, headers=self.client.HEADERS
        )


    @patch('requests.get')
    def test_getting_secret_versions(self, mock_get):
        """ get_secret_versions: Ensure that the version information of a secret is returned """
        version_data = {
					 'has_next': False,
					 'next_offset': None,
					 'limit': 1,
					 'offset': 1,
					 'version_count_in_result': 1,
					 'total_version_count': 2,
					 'secure_data_version_summaries': [{'id': '00000000-0000-0000-0000-000000012345',
							 'sdbox_id': '244cfc0d-4beb-8189-5056-194f18ead6f4',
							 'path': 'fake/path',
							 'action': 'UPDATE',
               'version_created_by': 'arn:aws:iam::292800423415:role/studio54-dancefloor',
               'version_created_ts': '1978-11-27T23:08:14.027Z',
							 'action_principal': 'arn:aws:iam::292800423415:role/studio54-dancefloor',
							 'action_ts': '1978-11-27T23:08:14.027Z'}]
        }

        mock_resp = self._mock_response(content=json.dumps(version_data))
        mock_get.return_value = mock_resp

        secrets = self.client.get_secret_versions('fake/path', limit=1, offset=1)

        # check to make sure we got the right secret
        assert_equals(secrets['limit'], 1)
        assert_equals(secrets['offset'], 1)
        assert_equals(secrets['secure_data_version_summaries'][0]['id'], '00000000-0000-0000-0000-000000012345')
        assert_equals(secrets['secure_data_version_summaries'][0]['path'], 'fake/path')
        assert_in('X-Cerberus-Client', self.client.HEADERS)
        mock_get.assert_called_with(
            self.cerberus_url + '/v1/secret-versions/fake/path',
            params={'limit': '1', 'offset': '1'},
            headers=self.client.HEADERS
        )


    @patch('requests.get')
    def test_get_secrets_invalid_path(self, mget):
        """ Ensure that a Cerberus exception is raised if the path is invalid. """
        data = json.dumps({"error_id": "123", "errors": []})
        mget.return_value = self._mock_response(status=401, content=data)
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
        data = json.dumps({"error_id": "123", "errors": []})
        mget.return_value = self._mock_response(status=401, content=data)
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

    @patch('requests.get')
    def test_request_headers_has_client_version(self, mock_get):
        secret_data = {
            "data": {
                "sushi": "ikenohana",
                "ramen": "yuzu"
            }
        }

        mock_resp = self._mock_response(content=json.dumps(secret_data))
        mock_get.return_value = mock_resp
        self.client.get_secrets_data("fake/path", "ramen")
        mock_get.assert_called_with(ANY, headers=AnyDictWithKey('X-Cerberus-Client'), params=ANY)

    @patch.dict('os.environ', {"CERBERUS_TOKEN": "dashboardtoken"})
    def test_environment_variable_overrides_user_auth(self):
        anotherClient = CerberusClient(
            self.cerberus_url,
            'testuser', 'hardtoguesspasswd'
        )
        assert_equals(anotherClient.get_token(), "dashboardtoken")

    @patch.dict('os.environ', {"CERBERUS_TOKEN": "dashboardtoken"})
    def test_environment_variable_overrides_default_auth(self):
        anotherClient = CerberusClient(
            self.cerberus_url
        )
        assert_equals(anotherClient.get_token(), "dashboardtoken")

    @patch.dict('os.environ', {"CERBERUS_TOKEN": "dashboardtoken"})
    def test_environment_variable_overrides_lambda_context(self):
        anotherClient = CerberusClient(
            self.cerberus_url, lambda_context="whatever object"
        )
        assert_equals(anotherClient.get_token(), "dashboardtoken")

    @patch.dict('os.environ', {"CERBERUS_TOKEN": "dashboardtoken"})
    def test_environment_variable_does_not_overrides_token_parameter(self):
        anotherClient = CerberusClient(
            self.cerberus_url, token="overridetoken"
        )
        assert_equals(anotherClient.get_token(), "overridetoken")