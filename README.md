# Cerberus Python Client

This is a Python based client library for communicating with Cerberus and Vault via HTTPS and enables authentication schemes specific
to AWS and Cerberus.

This client currently supports read-only operations (write operations are not yet implemented, feel free to open a
pull request to implement write operations)

To learn more about Cerberus, please visit the [Cerberus website](http://engineering.nike.com/cerberus/).

## Installation

```bash
pip install https://github.com/Nike-Inc/cerberus-python-client.git
```


## Usage

```python
from cerberus_client import CerberusClient
```

```python
client = CerberusClient(username, password))
```
