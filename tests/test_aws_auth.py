# Stuff for tests...
from unittest.mock import Mock, patch
from nose.tools import assert_equals

# other stuff
import json
import boto3
from moto import mock_kms

# Local imports...
from cerberus.aws_auth import AWSAuth

class TestAWSAuth(object):

    @classmethod
    @patch('cerberus.aws_auth.AWSAuth.set_auth')
    def setup_class(self, mock_auth):
        self.client = AWSAuth("https://cerberus.fake.com")


    @mock_kms
    @patch('requests.post')
    def test_get_token(self,mock_post):
        """unit test for get token"""
        client = boto3.client('kms', region_name='us-west-2')
        response = client.decrypt('ZW5jcnlwdG1l'.encode('utf-8'))
        response['Plaintext'].should.equal('encryptme')
