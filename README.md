# Cerberus Python Client

This is a Python based client library for communicating with Cerberus and Vault via HTTPS and enables authentication schemes specific
to AWS and Cerberus.

This client currently supports read-only operations (write operations are not yet implemented, feel free to open a
pull request to implement write operations)

To learn more about Cerberus, please visit the [Cerberus website](http://engineering.nike.com/cerberus/).

## Installation
This is a Python 3 project.

Install the python required packages:
```bash
  $ pip3 install -r requirements.txt
```

Install the client:
```bash
pip3 install https://github.com/Nike-Inc/cerberus-python-client.git
```


## Usage

```python
from cerberus.client import CerberusClient
```

To use with a username and password (CLI usage)
```python
client = CerberusClient(https://my.cerberus.url, username, password)
```

To use with IAM role (most common usage)
```python
client = CerberusClient(https://my.cerberus.url)
```

To get a secret for specific keys
```python
secret = client.get_secret(path, key)
```

To get all the secrets for a vault path
```python
secrets = client.get_secrets(path)
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
