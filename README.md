# Cerberus Python Client

[![][travis img]][travis]
[![][license img]][license]
[![PyPI version](https://badge.fury.io/py/cerberus-python-client.svg)](https://badge.fury.io/py/cerberus-python-client)

This is a Python based client library for communicating with Cerberus via HTTPS and enables authentication schemes specific
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


IAM Role Authentication(Local, EC2, ECS, Lambda, etc.):

```python
client = CerberusClient('https://my.cerberus.url')
```

User Authentication:
```python
client = CerberusClient('https://my.cerberus.url', username, password)
```

Authentication Through an Assumed Role:
```python
sts = boto3.client('sts')
role_data = sts.assume_role(RoleArn = 'arn:aws:iam::0123456789:role/CerberusRole', RoleSessionName = "CerberusAssumeRole")
creds = role_data['Credentials']

# Cerberus can be passed a botocore or boto3 session to use for authenticating with the Cerberus Server.
cerberus_session = boto3.session.Session(
    region_name = 'us-east-1',
    aws_access_key_id = creds['AccessKeyId'],
    aws_secret_access_key = creds['SecretAccessKey'],
    aws_session_token = creds['SessionToken']
)

client = CerberusClient(cerberus_url='https://my.cerberus.url', aws_session=cerberus_session)

```

#### Activate Log Messages

```python
from cerberus.client import CerberusClient
import logging

# Logging has to be imported and the root level logger needs to be configured
#  before you instantiate the client
logging.basicConfig(level=logging.INFO)

client = CerberusClient('https://my.cerberus.url')
```

#### Surpress debug messages
```python
# By default the Cerberus client will log some helpful messages to stderr
# setting verbose to False will surpress these messages.
client = CerberusClient('https://my.cerberus.url', verbose=False)
```

#### Read Secrets from Cerberus

To list what secrets are in a safe deposit box:
```python
client.list_secrets('app/safe-deposit-box')
```

To get a secret for a specific key in a safe deposit box:
```python
client.get_secrets_data("app/path/to/secret")["secretName"]
```

** Note: If you need to get more than one key, it's best to use the following example to get all the secrets at once instead of calling get_secrets_data multiple times.

To get all the secrets for an safe deposit box:
```python
client.get_secrets_data("app/path/to/secret")
```

To view the available versions of a secret in a safe deposit box:
```python
client.get_secret_versions("app/path/to/secret")

#optionally you can pass a limit and offset to limit the output returned and paginate through it.

client.get_secret_versions("app/path/to/secret", limit=100, offset=0)
```

To get a secret at a specific version:
```python
client.get_secrets_data("app/path/to/secret", version='<version id>')
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


#### Read files from Cerberus

To list files in Cerberus
```python
client.list_files('category/path/')
```

To download a file and its metadata
```python
client.get_file('category/sdb/path/to/file.example')

## Returns
{'Date': 'Thu, 10 May 2018 00:37:47 GMT',
 'Content-Type': 'application/octet-stream; charset=UTF-8',
 'Content-Length': '36',
 'Connection': 'keep-alive',
 'Content-Disposition': 'attachment; filename="file.example"',
 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
 'X-B3-TraceId': 'f403214321',
 'Content-Encoding': 'gzip',
 'filename': 'file.example',
 'data': b'example file. With binary data \xab\xba\xca\xb0'}
```
The key `'filename'` is generated by the library.
The key `'data'` contains the binary file data

Download a file at a specific version
```python
client.get_file('category/sdb/path/to/file.example', 'version id')
```

To view available versions for a file
```python
client.get_file_versions('category/sdb/path/to/file.example')
```

To download just the file data
```python
client.get_file_data('category/sdb/path/to/file.example')

## Returns
b'example file. With binary data \xAB\xBA\xCA\xB0'
```

To download just the file metadata
```python
client.get_file_metadata('category/sdb/path/to/file.example')

## Returns
{'Date': 'Thu, 10 May 2018 00:57:00 GMT',
 'Content-Type': 'application/octet-stream; charset=UTF-8',
 'Content-Length': '36',
 'Connection': 'keep-alive',
 'Content-Disposition': 'attachment; filename="test.py"',
 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
 'X-B3-TraceId': 'beede324324324'}
```


#### Upload a file to Cerberus

Uploading a file to Cerberus
```python
## put_file('SDB Path', 'file name', file handle to file you want to upload)
client.put_file('category/sdb/path/to/file.example', open('file.example', 'rb'))
```
For the file you open, please make sure it's opened in binary mode, otherwise the size calculations for how big it is can be off.


#### Delete a file in Cerberus

```python
client.delete_file('category/sdb/path/to/file.example')
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


#### Lambda examples

Get secrets from Cerberus using IAM Role (execution role) ARN. It's a good idea to cache the secrets since AWS reuses Lambda instances.
```python
from cerberus.client import CerberusClient
secrets = None
def lambda_handler(event, context):
    if secrets is None:
        client = CerberusClient('https://my.cerberus.url')
        secrets = client.get_secrets_data("app/yourapplication/dbproperties")['dbpasswd']
```

### Admin

A Cerberus admin (not to be confused with SDB owners) may perform additional tasks such as getting SDB metadata. 

#### Metadata

Get all SDB metadata from Cerberus.
```python
from cerberus.client import CerberusClient
metadata = CerberusClient('https://my.cerberus.url').get_metadata()
```

Get SDB metadata of a specific SDB from Cerberus.
```python
from cerberus.client import CerberusClient
metadata = CerberusClient('https://my.cerberus.url').get_metadata(sdb_name='my sdb')
```

## Running Tests

You can run all the unit tests using nosetests. Most of the tests are mocked.

```bash
$ nosetests --verbosity=2 tests/
```


## Local Development

The easiest way to locally test the Python client is to first authenticate with Cerberus through the dashboard, then use your dashboard authentication token to make subsequent calls. See examples below.
```python
from cerberus.client import CerberusClient
client = CerberusClient('https://my.cerberus.url') # This will work on an EC2 instance. But it will fail on local when it tries to call the metadata endpoint.
```
Without changing any code, set the `CERBERUS_TOKEN` system environment variable:
```bash
$ export CERBERUS_TOKEN='mytoken'
```
```python
from cerberus.client import CerberusClient
client = CerberusClient('https://my.cerberus.url') # On local, the client will pick up the environment variable that was set earlier. When it's deployed to an EC2 instance that doesn't have the `CERBERUS_TOKEN` system environment variable, it'll automatically switch to authenticating using the metadata endpoint.
```
Alternatively, you can pass in the token directly.
```python
from cerberus.client import CerberusClient
client = CerberusClient('https://my.cerberus.url', token='mytoken')
```
Refer to the "local development" section at [Quick Start](http://engineering.nike.com/cerberus/docs/user-guide/quick-start) if you're having trouble getting a token.


## License

Cerberus Management Service is released under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

[travis]:https://travis-ci.org/Nike-Inc/cerberus-python-client
[travis img]:https://api.travis-ci.org/Nike-Inc/cerberus-python-client.svg?branch=master

[license]:LICENSE.txt
[license img]:https://img.shields.io/badge/License-Apache%202-blue.svg
