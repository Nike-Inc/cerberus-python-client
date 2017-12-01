__all__ = ['client', 'user_auth', 'aws_auth']

CLIENT_VERSION = '0.8.0'


class CerberusClientException(Exception):
    """Wrap third-party exceptions expected by the Cerberus client."""
    pass
