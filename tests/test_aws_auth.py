# Stuff for tests...
import base64
import json
import unittest

import boto3
import requests
from mock import patch
from moto import mock_kms
from moto import mock_sts

from cerberus.aws_auth import AWSAuth


class TestAWSAuth(unittest.TestCase):

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

    """
    A bug in the Moto library is causing problems for Python 3+ on this test.  As a result, this test has been
    commented out until a fix can be put in place.
    """
    # @patch('requests.post')
    # @mock_kms
    # @mock_sts
    # def test_get_token(self, mock_post):
    #     # Example Cerberus response.
    #     response_body = {
    #         "client_token": "9a8b5f0e-b41f-3fc7-1c94-3ed4a8057396",
    #         "policies": [
    #             "web"
    #         ],
    #         "metadata": {
    #             "account_id": "123",
    #             "iam_role_name": "web"
    #         },
    #         "lease_duration": 3600,
    #         "renewable": True
    #     }
    #
    #     client = boto3.client('kms')
    #     key_data = client.create_key()
    #     key_id = key_data['KeyMetadata']['KeyId']
    #
    #     cipher_data = client.encrypt(KeyId=key_id, Plaintext=json.dumps(response_body))
    #
    #     mock_post.return_value = self._mock_response(
    #         content=json.dumps({'auth_data': cipher_data['CiphertextBlob'].decode('utf-8')})
    #     )
    #
    #     # Test the AWSAuth client leveraging default role ARN and region detection...
    #     auth_client = AWSAuth("https://cerberus.fake.com")
    #     token = auth_client.get_token()
    #     self.assertEqual(token, response_body['client_token'])
    #
    #     # Now we'll make sure that it works w/ a supplied role ARN and region...
    #     test_account = '123456789012'
    #     test_role = 'test_role'
    #
    #     auth_client = AWSAuth(
    #         "https://cerberus.fake.com",
    #         "arn:aws:iam::" + test_account + ":role/" + test_role,
    #         "us-east-1"
    #     )
    #     self.assertEqual(auth_client.account_id, test_account)
    #     self.assertEqual(auth_client.role_name, test_role)
    #
    #     token = auth_client.get_token()
    #     self.assertEqual(token, response_body['client_token'])
