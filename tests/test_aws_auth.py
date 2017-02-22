# Stuff for tests...
from unittest.mock import Mock, patch
from nose.tools import raises, assert_equals, assert_dict_equal

# other stuff
import json
import boto3
from requests.exceptions import HTTPError

# Local imports...
from cerberus.aws_auth import AWSAuth

class TestAWSAuth(object):

    @classmethod
    @patch('cerberus.aws_auth.AWSAuth.set_auth')
    def setup_class(self, mock_auth):
        self.client = AWSAuth("https://cerberus.fake.com")


    @patch('requests.post')
    def test_get_token(self,mock_post):
        """unit test for get token"""
