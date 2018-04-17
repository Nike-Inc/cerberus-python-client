from requests.exceptions import RequestException
from . import CerberusClientException
import json

def throw_if_bad_response(response):
    """Throw an exception if the Cerberus response is not successful."""
    try:
        response.raise_for_status()
    except RequestException as e:
        msg = 'Response code: {}; response body:\n{}'.format(response.status_code, json.dumps(response.json(), indent=2))
        raise CerberusClientException(msg)
