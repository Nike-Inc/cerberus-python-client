__all__ = ['client', 'user_auth', 'aws_auth', 'util']

CLIENT_VERSION = '2.1.2'


class CerberusClientException(Exception):
    """Wrap third-party exceptions expected by the Cerberus client."""
    pass
