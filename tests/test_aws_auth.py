# Stuff for tests...
import json

import boto3
from mock import patch
from moto import mock_kms
from moto import mock_sts

from cerberus.aws_auth import AWSAuth


class TestAWSAuth(object):

    @classmethod
    @mock_sts
    def setup_class(cls):
        cls.client = AWSAuth("https://cerberus.fake.com")

    @patch('requests.post')
    @mock_kms
    def test_get_token(self, mock_post):
        """unit test for get token"""
        response_body = {
            "auth": {
                "client_token": "9a8b5f0e-b41f-3fc7-1c94-3ed4a8057396",
                "policies": [
                    "web"
                ],
                "metadata": {
                    "account_id": "123",
                    "iam_role_name": "web"
                },
                "lease_duration": 3600,
                "renewable": True
            }
        }

        client = boto3.client('kms')
        key_data = client.create_key()
        key_id = key_data['KeyMetadata']['KeyId']
        cipher_data = client.encrypt(KeyId=key_id, Plaintext=json.dumps(response_body))

        mock_post.return_value = json.dumps({'auth_data': cipher_data['CiphertextBlob']})
