# Setting up logging here because this is the root of the module
import logging

__all__ = ['client', 'user_auth', 'aws_auth', 'util']

CLIENT_VERSION = '2.5.1'

class CerberusClientException(Exception):
    """Wrap third-party exceptions expected by the Cerberus client."""
    pass

# This avoids the "No handler found" warnings.
logging.getLogger(__name__).addHandler(logging.NullHandler())

