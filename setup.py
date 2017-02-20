from setuptools import setup, find_packages

setup(
    name='cerberus python client',
    version='0.1.0',
    author='Ann Wallace'
    author_email='ann.wallace@nike.com'
    description="A python client for interacting with Cerberus and Valut",
    packages=find_packages(exclude=('tests', 'docs'))
    test_suite="tests",
  )
