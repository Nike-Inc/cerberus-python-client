from requests.exceptions import RequestException
from . import CerberusClientException
import json
import requests
import time


def throw_if_bad_response(response):
    """Throw an exception if the Cerberus response is not successful."""
    try:
        response.raise_for_status()
    except RequestException as e:
        msg = 'Response code: {}; response body:\n{}'.format(response.status_code, json.dumps(response.json(), indent=2))
        raise CerberusClientException(msg)


def get_with_retry(url, retry=3, **kwargs):
    return request_with_retry(url, 'get', retry, **kwargs)


def post_with_retry(url, retry=3, **kwargs):
    return request_with_retry(url, 'post', retry, **kwargs)


def put_with_retry(url, retry=3, **kwargs):
    return request_with_retry(url, 'put', retry, **kwargs)


def delete_with_retry(url, retry=3, **kwargs):
    return request_with_retry(url, 'delete', retry, **kwargs)


def head_with_retry(url, retry=3, **kwargs):
    return request_with_retry(url, 'head', retry, **kwargs)


def request_with_retry(url, verb, retry, **kwargs):
    request = {'get': requests.get,
               'post': requests.post,
               'put': requests.put,
               'delete': requests.delete,
               'head': requests.head}
    resp = None
    for retry_attemp_number in range(retry):
        resp = request[verb](url, **kwargs)
        if not resp.status_code >= 500:
            return resp
        else:
            # exponential backoff
            time.sleep(2**retry_attemp_number)
    return resp
