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

To list what secrets are in a safe deposit box:
```python
client.list_secrets('app/safe-deposit-box')
```

To get a secret for a specific key in a safe deposit box:
```python
client.get_secret("app/path/to/secret", "secretName")
```

To get all the secrets for an safe deposit box:
```python
client.get_secrets("app/path/to/secret")
```

#### Write Secrets to Cerberus

To write a secret to a safe deposit box:
```python
client.put_secret("app/path/to/secret", {'key-name': 'value to store'})
```
By default `put_secret` will attempt to merge the dictionary provided with what already exists in the safe deposit box.  If you want to overwrite the stored dictionary in the safe deposit box called put_secret with merge=False.
```python
client.put_secret("app/path/to/secret", {'new-keys': 'new values'}, merge=False)
```

#### View roles and categories

Roles are the permission scheme you apply to an AD group or IAM roles to allow reading or writing secrets.  To view the available roles and their ids:
```python
client.get_roles()
```
This will return a list of dictionaries with all the roles.

A convience function is available that will return a dictionary with the role names as keys, and the role id as values.
```python
client.list_roles()
```
If you know the role name you need are are trying to get the id for it:
```python
client.get_role('role-name')
```
That will return a string containing the role id.

Categories are for organizing safe deposit boxes.  To list the available categories:
```python
client.get_categories()
```

#### Create a Safe Deposit Box

To create a new Safe Deposit Box:
```python
client.create_sdb(
  'Name of Safe Deposit Box',
  'category_id',
  'owner_ad_group',
  description = 'description',
  user_group_permissions=[{ 'name': 'ad-group', 'role_id': 'role id for permissions'}],
  iam_principal_permissions=[{'iam_principal_arn': 'arn:aws:iam:xxxxxxxxxx:role/role-name', 'role_id': 'role id for permissions'}]
)
```
You will recieve a json response giving you the details of your new safe deposit box.  As a note, you usually have to refresh your tokens before you are able to write secrets to the new safe deposit box.

#### Update a Safe Deposit Box

To update a Safe Deposit Box:
```python
client.update_sdb(
  'sdb_id',
  owner='owner ad group',
  description='description of safe deposit box',
  user_group_permissions=[{'name': 'ad group', 'role_id': 'role id for permissions'}],
  iam_principal_permissions=[{'iam_principal_arn': 'arn:aws:iam:xxxxxxxxxx:role/role-name', 'role_id': 'role id for permissions'}]
)
```
When updating, if you don't specify a parameter, the current values in the safe deposit box will be kept.  So you don't need to include the description, or iam_principal_permissions if you're only updating the user_group_permissions.
Unlike put_secret, no attempt is made to merge the permissions dictionaries for you, so if you are adding a new user group, you must include the already existing user groups you want to keep in your update call.

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
** Note: The auth class authenticates with Cerberus using the given role, then tries to assume that role in order to decrypt the Cerberus auth payload.


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
