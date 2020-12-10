"""
Copyright 2018-present Nike, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
You may not use this file except in compliance with the License.
You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and* limitations under the License.*
"""

import unittest
from cerberus.url_util import ensure_single_trailing_slash, ensure_no_trailing_slash


class TestEnsureTrailingSlash(unittest.TestCase):
    """unit tests for url_util.ensure_trailing_slash"""

    @staticmethod
    def test_no_trailing_slash():
        url_with_trailing_slash = ensure_single_trailing_slash("nike.com")
        assert url_with_trailing_slash.endswith(".com/")

    @staticmethod
    def test_single_trailing_slash():
        url_with_trailing_slash = ensure_single_trailing_slash("nike.com/")
        assert url_with_trailing_slash.endswith(".com/")

    @staticmethod
    def test_multiple_trailing_slash():
        url_with_trailing_slash = ensure_single_trailing_slash("nike.com//")
        assert url_with_trailing_slash.endswith(".com/")


class TestEnsureNoTrailingSlash(unittest.TestCase):
    """unit tests for url_util.ensure_trailing_slash"""

    @staticmethod
    def test_no_trailing_slash():
        url_without_trailing_slash = ensure_no_trailing_slash("nike.com")
        assert url_without_trailing_slash.endswith(".com")

    @staticmethod
    def test_one_trailing_slash():
        url_without_trailing_slash = ensure_no_trailing_slash("nike.com/")
        assert url_without_trailing_slash.endswith(".com")

    @staticmethod
    def test_multiple_trailing_slash():
        url_without_trailing_slash = ensure_no_trailing_slash("nike.com//")
        assert url_without_trailing_slash.endswith(".com")
