from setuptools import setup, find_packages

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name='cerberus python client',
    version='0.1.2',
    install_requires=requirements,
    author='Ann Wallace',
    author_email='ann.wallace@nike.com',
    description="A python client for interacting with Cerberus and Vault",
    url='https://github.com/Nike-Inc/cerberus-python-client',
    license='Apache License, v2.0',
    keywords='cerberus nike',
    packages=find_packages(exclude=('tests', 'docs')),
    test_suite="tests",
  )
