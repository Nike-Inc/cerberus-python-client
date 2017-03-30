# Cerberus Python Client

[![][travis img]][travis]
[![][license img]][license]
[![PyPI version](https://badge.fury.io/py/cerberus-python-client.svg)](https://badge.fury.io/py/cerberus-python-client)

This is a Python based client library for communicating with Cerberus and Vault via HTTPS and enables authentication schemes specific
to AWS and Cerberus.

This client currently supports read-only operations (write operations are not yet implemented, feel free to open a
pull request to implement write operations)

To learn more about Cerberus, please visit the [Cerberus website](http://engineering.nike.com/cerberus/).

## Installation
This is a Python 3 project but should be compatible with python 2.7.

Install the cerberus python client and required python packages:
```bash
python3 setup.py install
```
or for python 2.7
```bash
python setup.py install
```

Or simply use pip or pip3
```bash
pip3 install cerberus-python-client
```

## Usage

```python
from cerberus.client import CerberusClient
```
This client supports 2 different types of authentication, both of which returns a Vault Token.

* username and password (CLI usage)
```python
client = CerberusClient(https://my.cerberus.url, username, password)
```

* EC2 IAM role (default mode)
```python
client = CerberusClient(https://my.cerberus.url)
```

To get a secret for a specific key
```python
secret = client.get_secret(path, key)
```

To get all the secrets for a vault path
```python
secrets = client.get_secrets(path)
```

If you simply want to get a token you can use the Auth classes.
You can also use the CerberusClient class.

* username and password
```python
from cerberus.user_auth import UserAuth
token = UserAuth('https://my.cerberus.url', 'username', 'password').get_token()'
```

* EC2 IAM role
```python
from cerberus.aws_auth import AWSAuth
token = AWSAuth('https://my.cerberus.url').get_token()
```

## Running Tests

You can run all the unit tests using nosetests. Most of the tests are mocked.

```bash
$ nosetests --verbosity=2 tests/
```

## Maintenance
This project is maintained by Ann Wallace `ann.wallace@nike.com`

## License

Cerberus Management Service is released under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

[travis]:https://travis-ci.org/Nike-Inc/cerberus-management-service
[travis img]:https://api.travis-ci.org/Nike-Inc/cerberus-management-service.svg?branch=master

[license]:LICENSE.txt
[license img]:https://img.shields.io/badge/License-Apache%202-blue.svg
