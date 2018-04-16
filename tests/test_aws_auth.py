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
import base64
import json
import unittest

import boto3
import requests
from mock import patch, ANY
from moto import mock_kms
from moto import mock_sts
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

    @patch('requests.get')
    @patch('requests.post')
    @mock_kms
    @mock_sts
    def test_get_token(self, mock_post, mock_get):

        # Example Cerberus response.
        response_body = {
            "client_token": "9a8b5f0e-b41f-3fc7-1c94-3ed4a8057396",
            "policies": [
                "web"
            ],
            "metadata": {
                "iam_principal_arn": "arn:aws:iam::123:role/web"
            },
            "lease_duration": 3600,
            "renewable": True
        }

        iam_info_response_body = {
            "Code" : "Success",
            "LastUpdated" : "2017-11-29T21:11:45Z",
            "InstanceProfileArn" : "arn:aws:iam::123:instance-profile/rolepath/instanceprofilename",
            "InstanceProfileId" : "AIPAJURSEGIIGKUJSHNXY"
        }

        iam_security_credentials_response_body = "rolename"

        client = boto3.client('kms', region_name='us-west-2')
        key_data = client.create_key()
        key_id = key_data['KeyMetadata']['KeyId']

        cipher_data = client.encrypt(KeyId=key_id, Plaintext=json.dumps(response_body).encode())

        mock_get.side_effect = [self._mock_response(content=iam_security_credentials_response_body),
                                self._mock_response(content=json.dumps(iam_info_response_body) )]

        mock_post.return_value = self._mock_response(
            content=json.dumps({'auth_data': base64.b64encode(cipher_data['CiphertextBlob']).decode()})
        )

        # Test the AWSAuth client leveraging default role ARN and region detection...
        auth_client = AWSAuth("https://cerberus.fake.com", region='us-east-1')
        mock_post.reset_mock()
        token = auth_client.get_token()
        mock_post.assert_called_once_with(ANY, data=ANY, headers=AnyDictWithKey('X-Cerberus-Client'))
        self.assertEqual(token, response_body['client_token'])
        self.assertEqual(auth_client.role_arn, "arn:aws:iam::123:role/rolepath/rolename")

        # Now we'll make sure that it works w/ a supplied role ARN and region...
        test_principal_arn = "arn:aws:iam::123456789012:role/test_role"

        auth_client = AWSAuth("https://cerberus.fake.com", test_principal_arn, "us-east-1")
        self.assertEqual(auth_client.role_arn, test_principal_arn)

        mock_post.reset_mock()
        token = auth_client.get_token()
        mock_post.assert_called_once_with(ANY, data=ANY, headers=AnyDictWithKey('X-Cerberus-Client'))
        self.assertEqual(token, response_body['client_token'])
