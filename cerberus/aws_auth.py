"""
Copyright 2016-present Nike, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
You may not use this file except in compliance with the License.
You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and*
limitations under the License.*
"""

# For python 2.7
from __future__ import print_function
from botocore import session, awsrequest, auth
from boto3.session import Session
import logging
import sys
import os
from datetime import datetime

from . import CerberusClientException, CLIENT_VERSION
from .network_util import throw_if_bad_response, post_with_retry
from collections import OrderedDict


logger = logging.getLogger(__name__)


def _get_aws_role_session_name():
    return os.environ.get(
        "AWS_ROLE_SESSION_NAME",
        "cerberus-python-client-{}".format(
            datetime.now()
            .replace(microsecond=0, tzinfo=None)
            .isoformat()
            .replace(":", "-")
            .replace(".", "-")
        ),
    )


def _get_aws_web_identity_token():
    web_identity_token = None
    web_identity_token_file = os.environ.get(
        "AWS_WEB_IDENTITY_TOKEN_FILE", ""
    )
    if web_identity_token_file:
        with open(web_identity_token_file, "r") as web_identity_token_file_io:
            web_identity_token = web_identity_token_file_io.read().strip()
    return web_identity_token


def _get_aws_credentials(aws_session=None):
    """
    Retrieve AWS credentials from a boto3 session.

    Parameters:

    - session (boto3.session.Session|None) = None: A boto3 session from
      which to infer credentials. If not provided, a session will be
      created using [AWS environment variables](https://go.aws/42HrK0R).
    """
    if not aws_session:
        arn = None
        profile_name = os.environ.get("AWS_PROFILE", None)
        aws_session = Session(
            profile_name=profile_name
        )
        if not profile_name:
            # We only infer an assumed AWS role if not using a profile.
            # For profiles, the assumed AWS role should be in
            # the profile parameters.
            arn = os.environ.get("AWS_ROLE_ARN", "")
            if arn:
                web_identity_token = _get_aws_web_identity_token()
                session_name = _get_aws_role_session_name()
                if web_identity_token:
                    credentials = session.client(
                        "sts"
                    ).assume_role_with_web_identity(
                        RoleArn=arn,
                        RoleSessionName=session_name,
                        WebIdentityToken=web_identity_token,
                    )["Credentials"]
                else:
                    credentials = session.client("sts").assume_role(
                        RoleArn=arn,
                        RoleSessionName=session_name,
                    )["Credentials"]
                aws_session = Session(
                    aws_access_key_id=credentials["AccessKeyId"],
                    aws_secret_access_key=credentials["SecretAccessKey"],
                    aws_session_token=credentials["SessionToken"],
                )
    return aws_session.get_credentials()


class AWSAuth(object):
    """Class to authenticate with an IAM Role"""
    CN_REGIONS = {"cn-north-1", "cn-northwest-1"}
    HEADERS = {"Content-Type": "application/json",
               "X-Cerberus-Client": "CerberusPythonClient/" + CLIENT_VERSION}

    def __init__(self, cerberus_url, region, aws_session=None, verbose=None):
        self.cerberus_url = cerberus_url
        self.region = region
        self.aws_session = aws_session
        self.verbose = verbose

    def _get_v4_signed_headers(self):
        """Returns V4 signed get-caller-identity request headers"""
        creds = _get_aws_credentials(self.aws_session)
        if creds is None:
            raise CerberusClientException("Unable to locate AWS credentials")
        readonly_credentials = creds.get_frozen_credentials()

        # hardcode get-caller-identity request
        data = OrderedDict((('Action', 'GetCallerIdentity'),
                            ('Version', '2011-06-15')))
        url = 'https://sts.{}.amazonaws.com'.format(self.region)
        if self.region in self.CN_REGIONS:
            url += ".cn"
        request_object = awsrequest.AWSRequest(method='POST',
                                               url=url, data=data)

        signer = auth.SigV4Auth(readonly_credentials, 'sts', self.region)
        signer.add_auth(request_object)
        return request_object.headers

    def get_token(self):
        """Returns a client token from Cerberus"""
        signed_headers = self._get_v4_signed_headers()
        for header in self.HEADERS:
            signed_headers[header] = self.HEADERS[header]

        resp = post_with_retry(self.cerberus_url + '/v2/auth/sts-identity',
                               headers=signed_headers)
        throw_if_bad_response(resp)

        token = resp.json()['client_token']
        iam_principal_arn = resp.json()['metadata']['aws_iam_principal_arn']
        if self.verbose:
            print('Successfully authenticated with Cerberus as {}'
                  .format(iam_principal_arn), file=sys.stderr)
        logger.info('Successfully authenticated with Cerberus as {}'
                    .format(iam_principal_arn))

        return token
