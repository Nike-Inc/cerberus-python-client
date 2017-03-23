__all__ = ['client', 'user_auth', 'aws_auth']

class CerberusClientException(Exception):
    """Wrap third-party exceptions expected by the Cerberus client."""
    pass
