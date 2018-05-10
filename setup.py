from setuptools import setup, find_packages
from cerberus import CLIENT_VERSION

setup(
    name='cerberus-python-client',
    version=CLIENT_VERSION,
    install_requires=[
        'boto3',
        'requests',
    ],
    author='Ann Wallace',
    author_email='ann.wallace@nike.com',
    description="A python client for interacting with Cerberus",
    url='https://github.com/Nike-Inc/cerberus-python-client',
    license='Apache License, v2.0',
    keywords='cerberus nike',
    packages=find_packages(exclude=('tests', 'docs')),
    test_suite="tests",
  )
