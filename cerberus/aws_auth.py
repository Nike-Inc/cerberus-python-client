import base64
import json
import re

import boto3
import requests


class AWSAuth(object):
    """Class to authenticate with an IAM Role"""
    cerberus_url = None
    account_id = None
    role_name = None
    region = None
    assume_role = False

    def __init__(self, cerberus_url, role_arn=None, region=None):
        self.cerberus_url = cerberus_url
        self.set_auth(role_arn, region)

    def set_auth(self, role_arn=None, region=None):
        """Sets the variables needed for AWS Auth"""
        client = boto3.client('sts')

        role_arn_match = None
        if role_arn is not None:
            role_arn_match = re.match(r'arn:aws:iam::(.*?):(?:role|instance-profile)/(.*)', role_arn)

        if role_arn_match is None:
            self.account_id = client.get_caller_identity().get('Account')
            self.role_name = client.get_caller_identity().get('Arn').split('/')[1]
        else:
            self.account_id = role_arn_match.group(1)
            self.role_name = role_arn_match.group(2)
            self.assume_role = True

        if region is None:
            session = boto3.session.Session()
            self.region = session.region_name
        else:
            self.region = region

    def get_token(self):
        """Returns a client token from Cerberus"""
        request_body = {
            'account_id': self.account_id,
            'role_name': self.role_name,
            'region': self.region
        }
        encrypted_resp = requests.post(self.cerberus_url + '/v1/auth/iam-role', data=json.dumps(request_body))

        if encrypted_resp.status_code != 200:
            encrypted_resp.raise_for_status()

        auth_data = encrypted_resp.json()['auth_data']
        if not self.assume_role:
            client = boto3.client('kms', region_name=self.region)
        else:
            sts = boto3.client('sts')
            role_data = sts.assume_role(
                RoleArn='arn:aws:iam::' + self.account_id + ':role/' + self.role_name,
                RoleSessionName='CerberusRole'
            )

            creds = role_data['Credentials']

            client = boto3.client(
                'kms',
                region_name=self.region,
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken']
            )

        response = client.decrypt(CiphertextBlob=base64.b64decode(auth_data))

        token = json.loads(response['Plaintext'].decode('utf-8'))['client_token']
        return token
