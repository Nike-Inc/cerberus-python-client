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

import base64
import json
import re
import os

import boto3
import requests

from . import CLIENT_VERSION
from .util import throw_if_bad_response, post_with_retry

class AWSAuth(object):
    """Class to authenticate with an IAM Role"""
    cerberus_url = None
    role_arn = None
    region = None
    assume_role = False

    HEADERS = {"Content-Type": "application/json", "X-Cerberus-Client": "CerberusPythonClient/" + CLIENT_VERSION}

    def __init__(self, cerberus_url, role_arn=None, region=None, assume_role=True):
        self.cerberus_url = cerberus_url
        self.set_auth(role_arn, region, assume_role)

    def set_auth(self, role_arn=None, region=None, assume_role=True):
        """Sets the variables needed for AWS Auth"""
        is_ecs = 'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI' in os.environ
        if role_arn is None:
            if is_ecs:
                self.get_ecs_role_arn()
            else:
                self.get_instance_role_arn()
        else:
            self.role_arn = role_arn
            self.assume_role = assume_role

        if region is None:
            self.region = self.get_ecs_region() if is_ecs else self.get_region()
        else:
            self.region = region

    def get_ecs_role_arn(self):
        relative_uri = os.environ['AWS_CONTAINER_CREDENTIALS_RELATIVE_URI']
        self.role_arn = requests.get('http://169.254.170.2'+relative_uri).json()['RoleArn']

    def get_instance_role_arn(self):
        sts_client = boto3.client('sts')
        role_name = self.get_role_name()

        instance_profile_arn = requests.get('http://169.254.169.254/latest/meta-data/iam/info').json()['InstanceProfileArn']
        m = re.match(r"arn:aws:iam::(.*?):instance-profile/(.*)", instance_profile_arn)
        account_id = m.group(1)
        instance_profile_path = m.group(2)

        if "/" in instance_profile_path:
            role_path = instance_profile_path.rsplit('/', 1)[0]
            role_with_path = role_path + "/" + role_name
        else:
            role_with_path = role_name

        self.role_arn = sts_client.get_caller_identity().get('Arn') if role_name is False \
            else "arn:aws:iam::" + account_id + ":role/" + role_with_path

    def get_role_name(self):
        """Returns role name from either ec2 or lambda"""
        try:
            # This is an EC2 instance, get the role name from the metadata service
            return requests.get('http://169.254.169.254/latest/meta-data/iam/security-credentials/').text
        except:
            pass

        try:
            # This is a Lambda, iam:GetRole is needed for this to work
            iam_client = boto3.client('iam')
            sts_client = boto3.client('sts')
            current_identity = sts_client.get_caller_identity()
            role_name = str(current_identity['Arn']).split('/')[-2]
            response = iam_client.get_role(RoleName=role_name)
            role_arn = response['Role']['Arn']
            role_arn_match = re.match(r'arn:aws:iam::.*?:(?:role|instance-profile)/(.*)', role_arn)
            return role_arn_match.group(1)
        except:
            pass

        return False

    def get_region(self):
        """Returns region from either ec2 or lambda"""
        try:
            # This is an EC2 instnace, get the region from the metadata service
            region = requests.get('http://169.254.169.254/latest/dynamic/instance-identity/document').json()['region']
            return region
        except:
            pass

        try:
            # This is a Lambda, get the region from the session
            session = boto3.session.Session()
            return session.region_name
        except:
            pass

        return False

    def get_ecs_region(self):
        """Returns region from ecs task"""
        # This is an ECS task, get the region from the metadata service
        task_arn = requests.get('http://169.254.170.2/v2/metadata').json()['TaskARN']
        m = re.match('arn:aws:ecs:(?P<region>.*):(.*):task/(.*)', task_arn)
        return m.group('region')

    def get_token(self):
        """Returns a client token from Cerberus"""
        request_body = {
            'iam_principal_arn': self.role_arn,
            'region': self.region
        }
        encrypted_resp = post_with_retry(self.cerberus_url + '/v2/auth/iam-principal', data=json.dumps(request_body),
                                       headers=self.HEADERS)

        if encrypted_resp.status_code != 200:
            throw_if_bad_response(encrypted_resp)

        auth_data = encrypted_resp.json()['auth_data']
        if not self.assume_role:
            client = boto3.client('kms', region_name=self.region)
        else:
            sts = boto3.client('sts')
            role_data = sts.assume_role(
                RoleArn=self.role_arn,
                RoleSessionName='CerberusAssumeRole'
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
