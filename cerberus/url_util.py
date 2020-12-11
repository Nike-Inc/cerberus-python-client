"""
Copyright 2020-present Nike, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
You may not use this file except in compliance with the License.
You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and* limitations under the License.*
"""


def ensure_single_trailing_slash(string):
    """ if a string doesn't end in a '/' add one """
    return str.join('', [ensure_no_trailing_slash(string), '/'])


def ensure_no_trailing_slash(string):
    """ if a string ends in a '/' remove it """
    while str.endswith(string, '/'):
        string = str(string[:-1])
    return str(string)
