# Changelog / Release Notes

All notable changes to `Cerberus Python Client` will be documented in this file. `Cerberus Python Client` adheres to [Semantic Versioning](http://semver.org/).
Date format is Day-Month-Year

### Added

###### 15-11-2018
- Version 2.0.0 - Add STS authentication support
- Remove KMS authentication
- Remove assume role

###### 22-10-2018
- Version 1.4.0 - Add basic support for multiple mfa device options

###### 25-07-2018
- Version 1.3.0 - Add support for ECS task
- Fix a bug where html error message would blow up the client

###### 01-06-2018
- Allow client to retry on 5xx responses

###### 11-05-2018
- Adds File support, including file versioning

###### 23-04-2018
- Version 1.0.0 - Add token parameter to override all other auth methods 
- Fix issue where the client version is not included in the HTTP head
- Prints useful error message when Cerberus call fails

###### 04-04-2018
- Version 0.12.0 - Added support for versioning of secrets in Cerberus.

###### 06-02-2018
- Fixes to `put_secret` method and updated supported verb as per [Cerberus API Docs](https://github.com/Nike-Inc/cerberus-management-service/blob/master/API.md#createupdate-secrets-at-a-path-post)

###### 30-11-2017
- Added support for paths in role ARN's - fix for [#13](https://github.com/Nike-Inc/cerberus-python-client/issues/13)

###### 28-11-2017
- Version 0.7.0 - Extend library to support creation, updates, and deletion of saftey deposit boxes and secrets.  Added some convience functions for getting and displaying information about an sdb, roles, and categories. 

###### 27-02-2017
- Added the ability for setting role ARN and region that differs from default for IAM role auth.

###### 23-02-2017
- Initial open source code drop for the Cerberus Python client by Ann Wallace.
