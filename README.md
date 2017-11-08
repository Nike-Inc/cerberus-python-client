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
** Note: This is a Python 3 project but should be compatible with python 2.7.


Clone this project and run one of the following from within the project directory:
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

Alternatively, add `cerberus-python-client` in the `install_requires` section of your project's `setup.py`.
Then run one of the following from within your projects directory:
```bash
python3 setup.py install
```
or for python 2.7
```bash
python setup.py install
```

## Usage

#### Import the Client:

```python
from cerberus.client import CerberusClient
```

#### Instantiate the Client


Default IAM Role Authentication:

```python
client = CerberusClient('https://my.cerberus.url')
```

Assumed IAM Role Authentication:
```python
client = CerberusClient('https://my.cerberus.url', role_arn='arn:aws:iam::0000000000:role/role-name')
```
** Note: In this case, the client authenticates with Cerberus using the given role, then tries to assume that role in order to decrypt the Cerberus auth payload.


User Authentication:
```python
client = CerberusClient('https://my.cerberus.url', username, password)
```

#### Read Secrets from Cerberus

To get a secret for a specific key in a safe deposit box:
```python
client.get_secret("app/path/to/secret", "secretName")
```

To get all the secrets for an safe deposit box:
```python
client.get_secrets("app/path/to/secret")
```

#### Get a Cerberus Authentication token

If you do not want to read a secret, but simply want an authentication token, then you can use one of the `<type>_auth.py` classes to retrieve a token.

You can also use the CerberusClient class.

* IAM Role Authentication
```python
from cerberus.aws_auth import AWSAuth
token = AWSAuth('https://my.cerberus.url').get_token()
```

* Assumed IAM Role Authentication:
```python
from cerberus.aws_auth import AWSAuth
token = AWSAuth('https://my.cerberus.url', 'arn:aws:iam::000000000:role/role-name').get_token()
```
** Note: The auth class authenticates Cerberus using the given role, then tries to assume that role in order to decrypt the Cerberus auth payload.


* User Authentication
```python
from cerberus.user_auth import UserAuth
token = UserAuth('https://my.cerberus.url', 'username', 'password').get_token()'
```


### Lambdas

Generally it does NOT make sense to store Lambda secrets in Cerberus for two reasons:

1. Cerberus cannot support the scale that lambdas may need, e.g. thousands of requests per second
1. Lambdas will not want the extra latency needed to authenticate and read from Cerberus

A better solution for Lambda secrets is using the [encrypted environmental variables](http://docs.aws.amazon.com/lambda/latest/dg/env_variables.html) 
feature provided by AWS.

Another option is to store Lambda secrets in Cerberus but only read them at Lambda deploy time, then storing them as encrypted 
environmental variables, to avoid the extra Cerberus runtime latency.

#### Prerequisites for Lambda

The IAM role assigned to the Lambda function must contain the following policy statement in addition to the above KMS decrypt policy, this is so the Lambda can look up its metadata to automatically authenticate with the Cerberus IAM auth endpoint:

```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "AllowGetRole",
        "Effect": "Allow",
        "Action": [
          "iam:GetRole"
        ],
        "Resource": [
          "*"
        ]
      }
    ]
  }
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
