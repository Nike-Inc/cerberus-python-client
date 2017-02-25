import base64
import json

import boto3
import requests


class AWSAuth(object):
    """Class to authenticate with an IAM Role"""

    def __init__(self, cerberus_url):
        self.cerberus_url = cerberus_url
        # aws creds
        self.account_id = None
        self.role_name = None
        self.region = None
        self.set_auth()

    def set_auth(self):
        """Sets the variables needed for AWS Auth"""
        client = boto3.client('sts')
        self.account_id = client.get_caller_identity().get('Account')
        self.role_name = client.get_caller_identity().get('Arn').split('/')[1]
        session = boto3.session.Session()
        self.region = session.region_name

    def get_token(self):
        """Returns a client token from Cerberus"""
        request_body = {
            'account_id': self.account_id,
            'role_name': self.role_name,
            'region': self.region
        }
        encrypted_resp = requests.post(self.cerberus_url + '/v1/auth/iam-role', data=json.dumps(request_body))
        encrypted_resp_json = json.loads(encrypted_resp.text)

        if encrypted_resp.status_code != 200:
            encrypted_resp.raise_for_status()

        auth_data = encrypted_resp_json['auth_data']
        client = boto3.client('kms')
        response = client.decrypt(CiphertextBlob=base64.b64decode(auth_data))

        token = json.loads(response['Plaintext'].decode('utf-8'))['client_token']
        return token
