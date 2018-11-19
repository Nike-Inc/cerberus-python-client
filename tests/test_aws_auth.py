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
import botocore
from mock import patch, ANY
from .matcher import AnyDictWithKey

from cerberus.aws_auth import AWSAuth


class TestAWSAuth(unittest.TestCase):
    """Mock unit test for aws_auth"""

    @staticmethod
    def _mock_response(status=200, reason=None, content=''):
        mock_resp = requests.Response()
        mock_resp.status_code = status
        # Reason the status code occurred.
        mock_resp.reason = reason
        # Raw content in byte
        mock_resp._content = bytes(content.encode('utf-8'))
        return mock_resp

    def _mock_decrypt(self):
        pass

    @patch('requests.post')
    @patch('botocore.session.Session.get_credentials')
    def test_get_token(self, mock_get_credentials, mock_post):
        # Example Cerberus response.
        response_body = {
            "client_token": "9a8b5f0e-b41f-3fc7-1c94-3ed4a8057396",
            "policies": [
                "web"
            ],
            "metadata": {
                "aws_iam_principal_arn": "arn:aws:iam::123:role/web"
            },
            "lease_duration": 3600,
            "renewable": True
        }
        mock_post.return_value = self._mock_response(
            content=json.dumps(response_body)
        )
        mock_get_credentials.return_value = botocore.credentials.Credentials('testid', 'testkey', 'testtoken')
        auth_client = AWSAuth("https://cerberus.fake.com", region='us-west-2')
        mock_post.reset_mock()
        token = auth_client.get_token()
        mock_post.assert_called_once_with(ANY, headers=AnyDictWithKey('X-Cerberus-Client'))
        mock_post.assert_called_once_with(ANY, headers=AnyDictWithKey('X-Amz-Date'))
        mock_post.assert_called_once_with(ANY, headers=AnyDictWithKey('X-Amz-Security-Token'))
        mock_post.assert_called_once_with(ANY, headers=AnyDictWithKey('Authorization'))
        self.assertEqual(token, response_body['client_token'])

    @patch('requests.post')
    def test_get_token_with_custom_aws_creds(self, mock_post):
        # Ideally this test should run in an environment with no AWS credentials to avoid false negative
        response_body = {
            "client_token": "9a8b5f0e-b41f-3fc7-1c94-3ed4a8057396",
            "policies": [
                "web"
            ],
            "metadata": {
                "aws_iam_principal_arn": "arn:aws:iam::123:role/web"
            },
            "lease_duration": 3600,
            "renewable": True
        }
        mock_post.return_value = self._mock_response(
            content=json.dumps(response_body)
        )
        creds = botocore.credentials.Credentials('testid', 'testkey', 'testtoken')
        auth_client = AWSAuth("https://cerberus.fake.com", region='us-west-2', aws_creds=creds)
        mock_post.reset_mock()
        token = auth_client.get_token()
        mock_post.assert_called_once_with(ANY, headers=AnyDictWithKey('X-Cerberus-Client'))
        mock_post.assert_called_once_with(ANY, headers=AnyDictWithKey('X-Amz-Date'))
        mock_post.assert_called_once_with(ANY, headers=AnyDictWithKey('X-Amz-Security-Token'))
        mock_post.assert_called_once_with(ANY, headers=AnyDictWithKey('Authorization'))
        self.assertEqual(token, response_body['client_token'])