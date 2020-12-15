"""
Copyright 2018-present Nike, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
You may not use this file except in compliance with the License.
You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and* limitations under the License.*
"""

import json
import unittest

import requests

from cerberus.network_util import throw_if_bad_response
from cerberus import CerberusClientException


class TestNetworkUtil(unittest.TestCase):
    """Mock unit test for network_util"""
    @staticmethod
    def _mock_response(status=200, reason=None, content=''):
        mock_resp = requests.Response()
        mock_resp.status_code = status
        # Reason the status code occurred.
        mock_resp.reason = reason
        # Raw content in byte
        mock_resp._content = bytes(content.encode('utf-8'))
        return mock_resp

    def test_html(self):
        resp = self._mock_response(status=403, content='<html>403 Unauthorized</html>')
        self.assertRaises(CerberusClientException, throw_if_bad_response, resp)

    def test_json(self):
        error_json = {'error_id': '1'}
        resp = self._mock_response(status=403, content=json.dumps(error_json))
        self.assertRaises(CerberusClientException, throw_if_bad_response, resp)
