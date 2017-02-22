import base64
import boto3
import json
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
        boto = boto3.client('sts')
        self.account_id = boto.get_caller_identity().get('Account')
        self.role_name = boto.get_caller_identity().get('Arn').split('/')[1]
        # get the region - couldn't figure out how to do this with boto3
        response = requests.get('http://169.254.169.254/latest/dynamic/instance-identity/document')
        self.region = json.loads(response.text)['region']

    def get_token(self):
        """Returns a clinet token from Cerberus"""
        request_body = {
            'account_id': self.account_id,
            'role_name': self.role_name,
            'region': self.region
        }
        encrypted_resp = requests.post(self.cerberus_url + '/v1/auth/iam-role',
                                        data=json.dumps(request_body))
        encrypted_resp_json = json.loads(encrypted_resp.text)
        if encrypted_resp.status_code != 200:
           encrypted_resp.raise_for_status()
        auth_data = encrypted_resp_json['auth_data']
        client = boto3.client('kms', region_name=self.region)
        response = client.decrypt(
            CiphertextBlob=base64.decodebytes(bytes(auth_data, 'utf-8'))
        )

        token = json.loads(response['Plaintext'].decode('utf-8'))['client_token']
        return token
