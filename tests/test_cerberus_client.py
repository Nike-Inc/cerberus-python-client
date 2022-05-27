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
import platform
from os.path import basename
import os
import copy

import requests
import mock
from mock import patch, ANY, mock_open
from nose.tools import assert_equals, assert_in, assert_is_not
from .matcher import AnyDictWithKey

from cerberus import CerberusClientException
from cerberus.client import CerberusClient
from cerberus.aws_auth import AWSAuth
from cerberus.user_auth import UserAuth

# Use the right builtins module for patching
if int(platform.python_version_tuple()[0]) < 3:
    builtins_str = "__builtin__"
else:
    builtins_str = "builtins"


class TestCerberusClient(unittest.TestCase):
    """Class to test the cerberus client. Mock is used to mock external calls"""

    @patch('cerberus.aws_auth.AWSAuth.get_token')
    @patch('cerberus.aws_auth.AWSAuth.__init__')
    @patch('cerberus.user_auth.UserAuth.get_token')
    @patch('cerberus.user_auth.UserAuth.__init__')
    def setUp(self, mock_ua_init, mock_ua_get_token, mock_awsa_init, mock_awsa_get_token):
        mock_ua_init.return_value = None
        mock_ua_get_token.return_value = "ua_token"

        mock_awsa_init.return_value = None
        mock_awsa_get_token.return_value = "awsa_token"

        self.cerberus_url = "https://cerberus.fake.com"
        self.client = CerberusClient(
            self.cerberus_url,
            'testuser', 'hardtoguesspasswd',
            verbose=True
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
            'iam_principal_permissions': [
                {'created_by': 'tester@studio54.com',
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
                 'role_id': '8609a0c3-31e5-49ab-914d-c70c35da9478'
                 }
            ],
        }
        self.create_sdb_data = {
            'id': '5f0-99-414-bc-e5909c',
            'name': 'Disco Events',
            'description': 'Studio 54',
            'path': 'app/disco-events/',
            'category_id': '244cfc0d-4beb-8189-5056-194f18ead6f4',
            'created_by': 'tester@studio54.com',
            'created_ts': '1978-11-27T23:08:14.027Z',
            'iam_principal_permissions': [
                {
                    'created_by': 'tester@studio54.com',
                    'iam_principal_arn': 'arn:aws:iam::292800423415:role/studio54-dancefloor',
                    'id': 'c8549195-5f2c-ba2c-eb0e-2605d1e58816',
                    'last_updated_by': 'tester@studio54.com',
                    'last_updated_ts': '1974-11-17T00:02:30Z',
                    'role_id': '8609a0c3-31e5-49ab-914d-c70c35da9478'
                },
                {
                    'created_by': 'tester@studio54.com',
                    'iam_principal_arn': 'arn:aws:iam::292800423415:role/studio54-bar',
                    'id': 'f57741a2-79c0-7e35-bbf9-82a32a1827eb',
                    'last_updated_by': 'tester@studio54.com',
                    'last_updated_ts': '1974-11-17T00:02:30Z',
                    'role_id': '8609a0c3-31e5-49ab-914d-c70c35da9478'
                },
                {
                    'created_by': 'tester@studio54.com',
                    'iam_principal_arn': 'arn:aws:iam::292800423415:role/studio54-office',
                    'id': '27731199-7055-3c4b-3883-9f01f17bc034',
                    'last_updated_by': 'tester@studio54.com',
                    'last_updated_ts': '1974-11-17T00:02:30Z',
                    'role_id': '8609a0c3-31e5-49ab-914d-c70c35da9478'
                }
            ],
            'owner': 'Admin.Studio.54',
            'user_group_permissions': []
        }
        self.file_data = {
            'Date': 'Sun, 17 November 1974 00:02:30 GMT',
            'Content-Type': 'image/png; charset=UTF-8',
            'Content-Length': '237',
            'Connection': 'keep-alive',
            'Content-Disposition': 'attachment; filename="test.png"',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'X-B3-TraceId': 'fa533432fe425da9',
            'filename': 'test.png',
            'data': '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x12\x00\x00\x00\x07\x08\x06\x00\x00\x00\x05\xd5\x1d\x7f\x00\x00\x00\x06bKGD\x00\xff\x00\xff\x00\xff\xa0\xbd\xa7\x93\x00\x00\x00\tpHYs\x00\x00\x0b\x13\x00\x00\x0b\x13\x01\x00\x9a\x9c\x18\x00\x00\x00\x07tIME\x07\xe2\x05\t\x16(\n\x87\x93H\xa5\x00\x00\x00\x19tEXtComment\x00Created with GIMPW\x81\x0e\x17\x00\x00\x00UIDAT\x18\xd3\x9d\x90A\n\xc0@\x08\x03\'e\xff\xff\xe5\xf4R\x8bX\xa5\xcbzs\xd0\x10F\xb6-\t\xdb\x9cL\xfc\nx\x13"L\x12\x95u<\xef+@\x0e\xa9\xcf\xf5\xa6\xe3k\xaa[\'7\xb0\xfdQ\xd1\x06M\xbe\xa6\xd6\x00\xd7\x8e\xcc??\x00\xf2\x13]=\xed\xc8\xce\xfc\x06\x0f\xbfK\x06s\xd8\x7f\x99\x00\x00\x00\x00IEND\xaeB`\x82'}
        # Json parsing is differnt on python 2.7
        if int(platform.python_version_tuple()[0]) < 3:
            self.file_data['data'] = "Test String"

    @staticmethod
    def _mock_response(status=200, reason='OK', content='', headers=''):
        mock_resp = requests.Response()
        mock_resp.status_code = status
        # Reason the status code occurred.
        mock_resp.reason = reason
        # Raw content in byte
        mock_resp._content = bytes(content.encode('utf-8'))
        mock_resp.headers = headers
        return mock_resp

    @staticmethod
    def _mock_response_raw(status=200, reason='OK', content=''):
        mock_resp = requests.Response()
        mock_resp.status_code = status
        # Reason the status code occurred.
        mock_resp.reason = reason
        mock_resp._content = bytes(content.encode('utf-8'))
        return mock_resp.json()

    @patch('cerberus.aws_auth.AWSAuth.get_token')
    @patch('cerberus.aws_auth.AWSAuth.__init__')
    @patch('cerberus.user_auth.UserAuth.get_token')
    @patch('cerberus.user_auth.UserAuth.__init__')
    @patch.dict('os.environ', {})
    def test_set_token(self, mock_ua_init, mock_ua_get_token, mock_awsa_init, mock_awsa_get_token):
        """ Testing set_token """
        mock_ua_init.return_value = None
        mock_ua_get_token.return_value = "ua_token"

        mock_awsa_init.return_value = None
        mock_awsa_get_token.return_value = "awsa_token"
        cerb_client = CerberusClient('https://foo', verbose=False)
        cerb_client.username = "foo"
        cerb_client._set_token()
        assert_equals(cerb_client.token, 'ua_token')

        cerb_client.username = None
        cerb_client._set_token()
        assert_equals(cerb_client.token, 'awsa_token')
        assert True

    @patch('requests.get')
    def test_list_roles(self, mock_get):
        mock_dict =  [{'created_by': 'system',
                       'id': 'foo',
                       'name': 'owner'},
                      {'created_by': 'system',
                       'id': 'foo',
                       'name': 'write'},
                      {'created_by': 'system',
                       'id': 'foo',
                       'name': 'read'}]

        mock_resp = self._mock_response(content=json.dumps(mock_dict))
        mock_get.return_value = mock_resp
        roles = self.client.list_roles()
        assert_equals(roles, {'owner': 'foo', 'write': 'foo', 'read': 'foo'})

        role = self.client.get_role("write")
        assert_equals(role, 'foo')

        with self.assertRaises(CerberusClientException):
            role = self.client.get_role("edit")

    @patch('requests.get')
    def test_get_categories(self, mock_get):
        mock_dict = [{'created_by': 'system',
                      'display_name': 'Applications',
                      'id': 'foo',
                      'path': 'app'},
                     {'created_by': 'system',
                      'display_name': 'Shared',
                      'id': 'bar',
                      'path': 'shared'}]

        mock_resp = self._mock_response(content=json.dumps(mock_dict))
        mock_get.return_value = mock_resp
        categories = self.client.get_categories()
        names = set([category['display_name'] for category in categories])
        assert_equals(names, set(['Applications', 'Shared']))

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

        with self.assertRaises(CerberusClientException):
            sdb_id = self.client.get_sdb_id_by_path("app/notfoundsdb/")

    @patch('requests.get')
    def test_get_sdb_secret_version_paths(self, mock_get):
        mock_get.return_value = self._mock_response(content=json.dumps([]))
        resp = self.client.get_sdb_secret_version_paths("2336d3-2375-f")
        assert_equals(resp, [])

    @patch('requests.get')
    def test_get_sdb_secret_version_paths_by_path(self, mock_get):
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
        empty_list_resp = self._mock_response(content=json.dumps([]))
        sdb_resp = self._mock_response(content=json.dumps(sdb_data))

        mock_get.side_effect = [sdb_resp, empty_list_resp]
        resp = self.client.get_sdb_secret_version_paths_by_path("app/snowflake/")
        assert_equals(resp, [])

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

    @patch('requests.get')
    def test_get_sdb_by_id(self, mock_get): #, mock_sdb_id):
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

    @patch('requests.get')
    def test_get_sdb_by_name(self, mock_get):
        """ Test that get_sdb_by_name returns some details of the sdb """

        mock_resp = self._mock_response(content=json.dumps(self.sdb_data))
        mock_get_sdbs_resp = self._mock_response(content=json.dumps([self.sdb_data]))
        mock_get.side_effect = [mock_get_sdbs_resp, mock_resp, mock_resp, mock_resp]

        # Calls:
        #     get_sdb_by_name -> get_sdb_by_id -> get_sdb_id -> get_sdbs

        details = self.client.get_sdb_by_name("Disco Events")

        assert_equals(details, self.sdb_data)
        assert_in('X-Cerberus-Client', self.client.HEADERS)
        mock_get.assert_called_with(
            self.cerberus_url + '/v2/safe-deposit-box/5f0-99-414-bc-e5909c',
            headers=self.client.HEADERS
        )

    @patch('requests.get')
    def test_get_sdb_by_path(self, mock_get):
        """ Test that get_sdb_by_path returns some details of the sdb """

        mock_resp = self._mock_response(content=json.dumps(self.sdb_data))
        mock_get_sdbs_resp = self._mock_response(content=json.dumps([self.sdb_data]))
        mock_get.side_effect = [mock_get_sdbs_resp, mock_resp, mock_resp, mock_resp]

        # Calls:
        #     get_sdb_by_path -> get_sdb_by_id -> get_sdb_id_by_path -> get_sdbs

        details = self.client.get_sdb_by_path("app/disco-events/")

        assert_equals(details, self.sdb_data)
        assert_in('X-Cerberus-Client', self.client.HEADERS)
        mock_get.assert_called_with(
            self.cerberus_url + '/v2/safe-deposit-box/5f0-99-414-bc-e5909c',
            headers=self.client.HEADERS
        )

    @patch('requests.get')
    def test_get_sdb_path(self, mock_get):
        """ Test that get_sdb_path returns the correct path """
        sdb_data = {
            "id": "5f0-99-414-bc-e5909c",
            "name": "Disco Events",
            "description": "Studio 54",
            "path": "app/disco-events/"
        }

        mock_resp = self._mock_response(content=json.dumps(self.sdb_data))
        mock_get_sdbs_resp = self._mock_response(content=json.dumps([self.sdb_data]))
        mock_get.side_effect = [mock_get_sdbs_resp, mock_resp, mock_resp]

        # Calls:
        #     get_sdb_path -> get_sdb_id -> get_sdbs

        path = self.client.get_sdb_path("Disco Events")

        assert_equals(path, sdb_data['path'])
        assert_in('X-Cerberus-Client', self.client.HEADERS)
        mock_get.assert_called_with(
            self.cerberus_url + '/v2/safe-deposit-box/5f0-99-414-bc-e5909c/',
            headers=self.client.HEADERS
        )

    @patch('requests.post')
    def test_create_sdb(self, mock_get):
        """ Test creation of sdb """
        mock_resp = self._mock_response(content=json.dumps(self.create_sdb_data))
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

        assert_equals(create, self.create_sdb_data)
        assert_in('X-Cerberus-Client', self.client.HEADERS)
        # mock_get.assert_called_once_with(self.cerberus_url + '/v2/safe-deposit-box') mock_get.assert_called_with(
        # self.cerberus_url + '/v2/safe-deposit-box', data={"owner": "Admin.Studio.54", "iam_principal_permissions":
        # [{"iam_principal_arn": "arn:aws:iam::292800423415:role/studio54-dancefloor", "role_id":
        # "8609a0c3-31e5-49ab-914d-c70c35da9478"}, {"iam_principal_arn":
        # "arn:aws:iam::292800423415:role/studio54-bar", "role_id": "8609a0c3-31e5-49ab-914d-c70c35da9478"},
        # {"iam_principal_arn": "arn:aws:iam::292800423415:role/studio54-office", "role_id":
        # "8609a0c3-31e5-49ab-914d-c70c35da9478"}], "description": "Studio 54", "category_id":
        # "244cfc0d-4beb-8189-5056-194f18ead6f4", "name": "Disco Events"}, headers=self.client.HEADERS )

    @patch('requests.put')
    @patch('requests.get')
    def test_update_sdb(self, mock_get, mock_put):
        """ Test creation of sdb """

        sdb_id =  self.create_sdb_data['id']
        old_iam_principals = self.create_sdb_data['iam_principal_permissions']
        updated_iam_principals = old_iam_principals[1:-1]
        updated_description = "new updated description"
        new_user_group_perms = [{'created_by': 'admin@arkansas.com',
                                 'created_ts': '2021-10-04T17:02:51.862Z',
                                 'id': '333334-fac3-eeee-bdbe-324ee6',
                                 'last_updated_by': 'admin@hamfest.com',
                                 'last_updated_ts': '2022-05-27T16:35:49.965Z',
                                 'name': 'Care.Dog',
                                 'role_id': 'fffeee3-b33f-1ee7-444-23435'}]

        new_sdb_data = copy.deepcopy(self.create_sdb_data)
        new_sdb_data['iam_principal_permissions'] = updated_iam_principals
        new_sdb_data['description'] = updated_description
        new_sdb_data['user_group_permissions'] = new_user_group_perms


        mock_get_resp = self._mock_response(content=json.dumps(self.create_sdb_data))
        mock_get.return_value = mock_get_resp
        mock_put_resp = self._mock_response(content=json.dumps(new_sdb_data))
        mock_put.return_value = mock_put_resp

        resp = self.client.update_sdb(sdb_id, owner="new_owner",
                                      description="new desc",
                                      user_group_permissions=new_user_group_perms,
                                      iam_principal_permissions=updated_iam_principals)

        assert_equals(resp['description'], updated_description)

        resp = self.client.update_sdb(sdb_id)
        assert_equals(resp['description'], updated_description)

        no_description_sdb = copy.deepcopy(self.create_sdb_data)
        del no_description_sdb['description']

        mock_get_resp = self._mock_response(content=json.dumps(no_description_sdb))
        mock_get.return_value = mock_get_resp

        resp = self.client.update_sdb(sdb_id, owner="new_owner",
                                      description="new desc",
                                      user_group_permissions=new_user_group_perms,
                                      iam_principal_permissions=updated_iam_principals)
        assert_equals(resp['description'], updated_description)

    @patch('requests.post')
    def test_create_sdb_bad_args(self, mock_post):
        sdb_data = {
            'id': '5f0-99-414-bc-e5909c',
            'name': 'Disco Events',
            'description': 'Studio 54',
            'path': 'app/disco-events/',
            'category_id': '244cfc0d-4beb-8189-5056-194f18ead6f4',
            'created_by': 'tester@studio54.com',
            'created_ts': '1978-11-27T23:08:14.027Z',
            'iam_principal_permissions': [],
            'owner': 'Admin.Studio.54',
            'description': 'test sdb',
            'user_group_permissions': []
        }
        mock_resp = self._mock_response(content=json.dumps(sdb_data))
        mock_post.return_value = mock_resp

        resp = self.client.create_sdb('Disco Events',
                                      '244cfc0d-4beb-8189-5056-194f18ead6f4',
                                      'Admin.Studio54', "test sdb")
        assert_equals(resp['path'], 'app/disco-events/')

        with self.assertRaises(TypeError):
            resp = self.client.create_sdb('Disco Events',
                                          '244cfc0d-4beb-8189-5056-194f18ead6f4',
                                          'Admin.Studio54', "test sdb",
                                          user_group_permissions={})

        with self.assertRaises(TypeError):
            resp = self.client.create_sdb('Disco Events',
                                          '244cfc0d-4beb-8189-5056-194f18ead6f4',
                                          'Admin.Studio54', "test sdb",
                                          iam_principal_permissions={})

        perms = [{'name': 'Nike.FGPP.Special.Accounts',
                  'role_id': '3e4e6cad-e05d-11e7-9e7d-027d629dcc88'}]

        sdb_data['user_group_permissions'] = perms

        mock_resp = self._mock_response(content=json.dumps(sdb_data))
        mock_post.return_value = mock_resp

        resp = self.client.create_sdb('Disco Events',
                                      '244cfc0d-4beb-8189-5056-194f18ead6f4',
                                      'Admin.Studio54', "test sdb",
                                      user_group_permissions=perms)
        assert len(resp['user_group_permissions'])

    @patch('requests.delete')
    def test_delete_sdb(self, mock_delete):
        sdb_data = {'category_id': '244cfc0d-4beb-8189-5056-194f18ead6f4',
                    'created_by': 'tester@studio54.com',
                    'created_ts': '1978-11-27T23:08:14.027Z',
                    'description': 'test sdb',
                    'iam_principal_permissions': [],
                    'id': '9a39f919-71b0-4a19-a1e5-0ba11adedf70',
                    'last_updated_by': 'tester@studio54.com',
                    'last_updated_ts': '2022-05-27T15:02:42.628Z',
                    'name': 'Disco Events',
                    'owner': 'Admin.Studio.54',
                    'path': 'app/disco-events/',
                    'user_group_permissions': []}
        mock_resp = self._mock_response(content=json.dumps(sdb_data))
        mock_delete.return_value = mock_resp

        resp = self.client.delete_sdb('9a39f919-71b0-4a19-a1e5-0ba11adedf70')
        assert resp.json()['path'] == 'app/disco-events/'

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

    # ---- files ----
    @patch('requests.get')
    def test_list_files(self, mock_get):
        """ Testing that list_files returns the correct files """
        list_data = {
            'has_next': False,
            'next_offset': None,
            'limit': 100,
            'offset': 0,
            'file_count_in_result': 3,
            'total_file_count': 3,
            'secure_file_summaries': [
                {
                    'sdbox_id': '244cfc0d-4beb-8189-5056-194f18ead6f4',
                    'path': 'studio54/test.py',
                    'size_in_bytes': 1323,
                    'name': 'test.py',
                    'created_by': 'tester@studio54.com',
                    'created_ts': '1974-11-17T00:02:30Z',
                    'last_updated_by': 'tester@studio54.com',
                    'last_updated_ts': '1974-11-17T00:02:30Z'
                },
                {
                    'sdbox_id': '244cfc0d-4beb-8189-5056-194f18ead6f4',
                    'path': 'studio54/test.gif',
                    'size_in_bytes': 686,
                    'name': 'test.gif',
                    'created_by': 'tester@studio54.com',
                    'created_ts': '1974-11-17T00:02:30Z',
                    'last_updated_by': 'tester@studio54.com',
                    'last_updated_ts': '1974-11-17T00:02:30Z'
                },
                {
                    'sdbox_id': '244cfc0d-4beb-8189-5056-194f18ead6f4',
                    'path': 'studio54/5621.gif',
                    'size_in_bytes': 686,
                    'name': '5621.gif',
                    'created_by': 'tester@studio54.com',
                    'created_ts': '1974-11-17T00:02:30Z',
                    'last_updated_by': 'tester@studio54.com',
                    'last_updated_ts': '1974-11-17T00:02:30Z'
                }
            ]
        }

        payload = {'limit': '100', 'offset': '0'}
        mock_resp = self._mock_response(content=json.dumps(list_data))
        mock_get.return_value = mock_resp

        keys = self.client.list_files('fake/path')

        assert_equals(keys['limit'], 100)
        assert_equals(keys['offset'], 0)
        assert_equals(keys, list_data)
        assert_in('X-Cerberus-Client', self.client.HEADERS)
        mock_get.assert_called_with(
            self.cerberus_url + '/v1/secure-files/fake/path/',
            params=payload, headers=self.client.HEADERS
        )

    @patch('requests.get')
    def test_getting_a_file(self, mock_get):
        """ get_file: Testing the correct file is returned"""

        headers = self.file_data.copy()
        del headers['data']
        mock_resp = self._mock_response(content=json.dumps(self.file_data), headers=headers)
        mock_get.return_value = mock_resp

        # Calls:
        #     get_file -> _get_file
        #                 _parse_metadata_filename

        secret_file = self.client.get_file('fake/path/test.png')

        # check to make sure we got the right file
        # assert_equals(secret_file, file_data)
        assert_in('X-Cerberus-Client', self.client.HEADERS)
        mock_get.assert_called_with(
            self.cerberus_url + '/v1/secure-file/fake/path/test.png',
            params={'versionId': 'CURRENT'}, headers=self.client.HEADERS
        )

    @patch('requests.get')
    def test_getting_file_data(self, mock_get):
        """ get_file_data: Testing the correct file data is returned"""

        mock_resp = self._mock_response(content=self.file_data['data'])
        mock_get.return_value = mock_resp

        secret_file = self.client.get_file_data('fake/path/test.png')

        # check to make sure we got the right file
        # assert_equals(secret_file, self.file_data['data'])
        assert_in('X-Cerberus-Client', self.client.HEADERS)
        mock_get.assert_called_with(
            self.cerberus_url + '/v1/secure-file/fake/path/test.png',
            params={'versionId': 'CURRENT'}, headers=self.client.HEADERS
        )

    @patch('requests.get')
    def test_getting_files_data_version(self, mock_get):
        """ get_file_data: Testing the correct files are returned when a version is passed """

        mock_resp = self._mock_response(content=json.dumps(self.file_data))
        mock_get.return_value = mock_resp

        files = self.client.get_file_data('fake/path/test.png', version='12345')

        # check to make sure we got the right file
        assert_in('X-Cerberus-Client', self.client.HEADERS)
        mock_get.assert_called_with(
            self.cerberus_url + '/v1/secure-file/fake/path/test.png',
            params={'versionId': '12345'}, headers=self.client.HEADERS
        )

    @patch('requests.get')
    def test_getting_file_versions(self, mock_get):
        """ get_file_versions: Ensure that the version information of a file is returned """
        version_data = {
            'has_next': False,
            'next_offset': None,
            'limit': 1,
            'offset': 1,
            'version_count_in_result': 1,
            'total_version_count': 2,
            'secure_data_version_summaries': [
                {
                    'id': '00000000-0000-0000-0000-000000012345',
                    'sdbox_id': '244cfc0d-4beb-8189-5056-194f18ead6f4',
                    'path': 'fake/path',
                    'action': 'UPDATE',
                    'version_created_by': 'arn:aws:iam::292800423415:role/studio54-dancefloor',
                    'version_created_ts': '1978-11-27T23:08:14.027Z',
                    'action_principal': 'arn:aws:iam::292800423415:role/studio54-dancefloor',
                    'action_ts': '1978-11-27T23:08:14.027Z'
                }
            ]
        }

        mock_resp = self._mock_response(content=json.dumps(version_data))
        mock_get.return_value = mock_resp

        files = self.client.get_file_versions('fake/path', limit=1, offset=1)

        # check to make sure we got the right file
        assert_equals(files['limit'], 1)
        assert_equals(files['offset'], 1)
        assert_equals(files['secure_data_version_summaries'][0]['id'], '00000000-0000-0000-0000-000000012345')
        assert_equals(files['secure_data_version_summaries'][0]['path'], 'fake/path')
        assert_in('X-Cerberus-Client', self.client.HEADERS)
        mock_get.assert_called_with(
            self.cerberus_url + '/v1/secret-versions/fake/path',
            params={'limit': '1', 'offset': '1'},
            headers=self.client.HEADERS
        )

    @patch("{0}.open".format(builtins_str), new_callable=mock_open, read_data="data")
    @patch('cerberus.network_util.request_with_retry')
    def test_put_file(self, mock_retry, mock_file):
        """ put_file: Test uploading a file   Especially that the incomming file name and sdb path are handled correctly """
        c_url = str.join("/", [self.cerberus_url, "v1/secure-file", self.sdb_data["path"]])
        sdb_path = self.sdb_data["path"]
        headers = self.client.HEADERS.copy()
        headers.pop('Content-Type', None)

        filenames = ["./test.txt", "/abs/path/test.txt", "no-ext", "./rel-no-ext", "/abs/path/no-ext",
                     "//start-with-double-slash"]
        f = filenames[0]
        for f in filenames:
            # Should have with self.subTests here, but python2 doesn't support that
            base_f = basename(f)
            assert_is_not(base_f, '', msg="Filename not found")
            mock_retry.return_value.status_code = 204
            mfile = open(f, 'rb')
            upload = self.client.put_file(str.join("", [sdb_path, base_f]), mfile)
            mock_retry.assert_called_with(c_url + base_f, 'post', 3, files={'file-content': (base_f, mfile)},
                                          headers=headers)

        headers['Content-Type'] = 'text/plain'
        resp = self.client.put_file(str.join("", [sdb_path, 'test.txt']), open('test.txt', 'rb'), content_type='text/plain')

        # ---- secrets ----

    @patch('requests.delete')
    def test_delete_file(self, mock_delete):
        mock_resp = self._mock_response(content=json.dumps(''))
        mock_delete.return_value = mock_resp

        secure_data_path = 'app/test.txt'
        resp = self.client.delete_file(secure_data_path)

        expected_url = self.cerberus_url + '/v1/secure-file/' + secure_data_path
        mock_delete.assert_called_with(expected_url,
                                       headers={'Content-Type': 'application/json',
                                                'X-Cerberus-Token': 'ua_token',
                                                'X-Cerberus-Client': 'CerberusPythonClient/2.5.3'})


    @patch('requests.delete')
    def test_delete_secret(self, mock_delete):
        mock_resp = self._mock_response(content=json.dumps(''))
        mock_delete.return_value = mock_resp

        secure_data_path = 'app/test/snack'
        resp = self.client.delete_secret(secure_data_path)

        expected_url = self.cerberus_url + '/v1/secret/' + secure_data_path
        mock_delete.assert_called_with(expected_url,
                                       headers={'Content-Type': 'application/json',
                                                'X-Cerberus-Token': 'ua_token',
                                                'X-Cerberus-Client': 'CerberusPythonClient/2.5.3'})


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
            'secure_data_version_summaries': [
                {
                    'id': '00000000-0000-0000-0000-000000012345',
                    'sdbox_id': '244cfc0d-4beb-8189-5056-194f18ead6f4',
                    'path': 'fake/path',
                    'action': 'UPDATE',
                    'version_created_by': 'arn:aws:iam::292800423415:role/studio54-dancefloor',
                    'version_created_ts': '1978-11-27T23:08:14.027Z',
                    'action_principal': 'arn:aws:iam::292800423415:role/studio54-dancefloor',
                    'action_ts': '1978-11-27T23:08:14.027Z'
                }
            ]
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
    def test_get_secrets_retry_on_5xx(self, mget):
        """Ensure that the client retries on 5xx response. """
        error_data = json.dumps({"error_id": "123", "errors": []})
        secret_data = json.dumps({
            "data": {
                "sushi": "ikenohana",
                "ramen": "yuzu"
            }
        })

        mget.side_effect = [self._mock_response(status=500, content=error_data),
                            self._mock_response(status=502, content=error_data),
                            self._mock_response(status=200, content=secret_data)]
        self.client.get_secrets_data('fake/path')

    @patch('requests.get')
    def test_get_secrets_retry_stop_after_limit(self, mget):
        """Ensure that the client does not retry too many times. """
        error_data = json.dumps({"error_id": "123", "errors": []})
        secret_data = json.dumps({
            "data": {
                "sushi": "ikenohana",
                "ramen": "yuzu"
            }
        })

        mget.side_effect = [self._mock_response(status=500, content=error_data),
                            self._mock_response(status=502, content=error_data),
                            self._mock_response(status=500, content=error_data),
                            self._mock_response(status=200, content=secret_data)]
        with self.assertRaises(CerberusClientException):
            self.client.get_secrets_data('fake/path')

    @patch('requests.get')
    def test_get_secrets_does_not_retry_on_200(self, mget):
        """ Ensure that the client does not retry on 200 response. """
        error_data = json.dumps({"error_id": "123", "errors": []})
        secret_data = json.dumps({
            "data": {
                "sushi": "ikenohana",
                "ramen": "yuzu"
            }
        })

        mget.side_effect = [self._mock_response(status=200, content=secret_data),
                            self._mock_response(status=500, content=error_data)]
        self.client.get_secrets_data('fake/path')

    @patch('requests.get')
    def test_get_secrets_does_not_retry_on_4xx(self, mget):
        """ Ensure that the client does not retry on 4xx response. """
        error_data = json.dumps({"error_id": "123", "errors": []})

        mget.side_effect = [self._mock_response(status=403, content=error_data),
                            self._mock_response(status=403, content=error_data)]
        with self.assertRaises(CerberusClientException):
            self.client.get_secrets_data('fake/path')
        mget.assert_called_once_with(
            self.cerberus_url + '/v1/secret/fake/path',
            params={'versionId': 'CURRENT'},
            headers=self.client.HEADERS
        )

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
            'testuser', 'hardtoguesspasswd',
            verbose=False
        )
        assert_equals(anotherClient.get_token(), "dashboardtoken")

    @patch.dict('os.environ', {"CERBERUS_TOKEN": "dashboardtoken"})
    def test_environment_variable_overrides_default_auth(self):
        anotherClient = CerberusClient(
            self.cerberus_url
        )
        assert_equals(anotherClient.get_token(), "dashboardtoken")

    @patch.dict('os.environ', {"CERBERUS_TOKEN": "dashboardtoken"})
    def test_environment_variable_does_not_overrides_token_parameter(self):
        anotherClient = CerberusClient(
            self.cerberus_url, token="overridetoken"
        )
        assert_equals(anotherClient.get_token(), "overridetoken")

    @patch('requests.get')
    def test_get_sdb_metadata(self, mock_get):
        """
        Testing that get_metadata returns the correct SDB metadata
        """
        metadata_1 = {
            'has_next': True,
            'next_offset': 1,
            'limit': 1,
            'offset': 0,
            'sdb_count_in_result': 1,
            'total_sdbcount': 2,
            'safe_deposit_box_metadata': [
                {
                    'name': 'sdb 1',
                    'path': 'app/sdb-1/',
                    'category': 'Applications',
                    'owner': 'very large group',
                    'user_group_permissions': {},
                    'iam_role_permissions':
                        {
                            'arn:aws:iam::1234567:role/role': 'write'
                        },
                    'data': None
                }
            ]
        }

        metadata_2 = {
            'has_next': False,
            'next_offset': 0,
            'limit': 1,
            'offset': 1,
            'sdb_count_in_result': 1,
            'total_sdbcount': 2,
            'safe_deposit_box_metadata': [
                {
                    'name': 'sdb 2',
                    'path': 'app/sdb-2/',
                    'category': 'Applications',
                    'owner': 'very large group',
                    'user_group_permissions': {},
                    'iam_role_permissions':
                        {
                            'arn:aws:iam::1234567:role/role': 'write'
                        },
                    'data': None
                }
            ]
        }

        mock_get.side_effect = [self._mock_response(content=json.dumps(metadata_1)),
                                self._mock_response(content=json.dumps(metadata_2))]
        metadata = self.client.get_metadata()

        # confirm the sdb names match
        assert_equals('sdb 1', metadata[0]['name'])
        assert_equals('sdb 2', metadata[1]['name'])
        assert_in('X-Cerberus-Client', self.client.HEADERS)
        mock_get.assert_called_with(
            self.cerberus_url + '/v1/metadata',
            params={'offset': 1},
            headers=self.client.HEADERS
        )

    @patch('requests.head')
    def test_get_file_metadata(self, mock_head):
        resp_dict = {'Date': 'Fri, 27 May 2022 18:37:56 GMT',
                     'Content-Type': 'text/plain', 'Content-Length': '4',
                     'Connection': 'keep-alive',
                     'Content-Disposition': 'attachment; filename="test.txt"'}
        mock_resp = self._mock_response(content=json.dumps(resp_dict))
        mock_head.return_value = mock_resp

        secure_data_path = 'app/test.txt'
        resp = self.client.get_file_metadata(secure_data_path)
        expected_url = self.cerberus_url + '/v1/secure-file/' + secure_data_path
        mock_head.assert_called_with(expected_url,
                                     params={'versionId': 'CURRENT'},
                                     headers={'Content-Type': 'application/json',
                                              'X-Cerberus-Token': 'ua_token',
                                              'X-Cerberus-Client': 'CerberusPythonClient/2.5.3'})

        resp = self.client.get_file_metadata(secure_data_path, version='3')
        mock_head.assert_called_with(expected_url,
                                     params={'versionId': '3'},
                                     headers={'Content-Type': 'application/json',
                                              'X-Cerberus-Token': 'ua_token',
                                              'X-Cerberus-Client': 'CerberusPythonClient/2.5.3'})
