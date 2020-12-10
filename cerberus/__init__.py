# Setting up logging here because this is the root of the module
import logging

__all__ = ['aws_auth', 'client', 'network_util', 'url_util', 'user_auth']

CLIENT_VERSION = '2.5.2'


class CerberusClientException(Exception):
    """Wrap third-party exceptions expected by the Cerberus client."""
    pass


# This avoids the "No handler found" warnings.
logging.getLogger(__name__).addHandler(logging.NullHandler())
