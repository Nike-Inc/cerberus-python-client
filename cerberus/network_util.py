
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

from requests.exceptions import RequestException
from . import CerberusClientException
import json
import requests
import time

DEFAULT_RETRY_ATTEMPT_NUMBER = 3


def throw_if_bad_response(response):
    """Throw an exception if the Cerberus response is not successful."""
    try:
        response.raise_for_status()
    except RequestException:
        try:
            msg = 'Response code: {}; response body:\n{}'.format(response.status_code, json.dumps(response.json(), indent=2))
            raise CerberusClientException(msg)
        except ValueError:
            msg = 'Response code: {}; response body:\n{}'.format(response.status_code, response.text)
            raise CerberusClientException(msg)


def get_with_retry(url, retry=DEFAULT_RETRY_ATTEMPT_NUMBER, **kwargs):
    return request_with_retry(url, 'get', retry, **kwargs)


def post_with_retry(url, retry=DEFAULT_RETRY_ATTEMPT_NUMBER, **kwargs):
    return request_with_retry(url, 'post', retry, **kwargs)


def put_with_retry(url, retry=DEFAULT_RETRY_ATTEMPT_NUMBER, **kwargs):
    return request_with_retry(url, 'put', retry, **kwargs)


def delete_with_retry(url, retry=DEFAULT_RETRY_ATTEMPT_NUMBER, **kwargs):
    return request_with_retry(url, 'delete', retry, **kwargs)


def head_with_retry(url, retry=DEFAULT_RETRY_ATTEMPT_NUMBER, **kwargs):
    return request_with_retry(url, 'head', retry, **kwargs)


def request_with_retry(url, verb, retry, **kwargs):
    request = {'get': requests.get,
               'post': requests.post,
               'put': requests.put,
               'delete': requests.delete,
               'head': requests.head}
    resp = None
    for retry_attempt_number in range(retry):
        resp = request[verb](url, **kwargs)
        if not resp.status_code >= 500:
            return resp
        else:
            # exponential backoff
            time.sleep(0.1 * 2 ** retry_attempt_number)
    return resp
