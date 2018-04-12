from requests.exceptions import RequestException
from . import CerberusClientException

def throw_if_bad_response(response):
    """Throw an exception if the Cerberus response is not successful."""
    try:
        response.raise_for_status()
    except RequestException as e:
        print('Cerberus error response:', response.content)
        raise CerberusClientException(str(e))
