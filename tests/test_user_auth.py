# Stuff for tests...
from unittest.mock import Mock, patch
from nose.tools import raises, assert_equals, assert_dict_equal

# other stuff
import json
from requests.exceptions import HTTPError

# Local imports...
from cerberus.user_auth import UserAuth

class TestUserAuth(object):

    @classmethod
    def setup_class(self):
        self.client = UserAuth(
                        "https://cerberus.fake.com",
                        'testuser',
                        'hardtoguesspasswd')
        self.auth_resp = """{"status": "mfa_req", "data":
                        {"username": "unicorn@rainbow.com",
                        "state_token": "0127a384d305138d4e",
                        "client_token": "None", "user_id": "1325",
                        "devices": [{"id": "223", "name":
                        "Google Authenticator"}]}}"""

    """
    modeled after https://goo.gl/WV2WGe
    """
    def _mock_response(
            self,
            status=200,
            content="STUFF",
            json_data=None,
            text="""{"key": "value"}""",
            raise_for_status=None):

        mock_resp = Mock()
        mock_resp.raise_for_status = Mock()
        if raise_for_status:
            mock_resp.raise_for_status.side_effect = raise_for_status
        mock_resp.status_code = status
        mock_resp.content = content
        mock_resp.text = text
        # add json data if provided
        if json_data:
            mock_resp.json = mock.Mock(
                return_value=json_data
            )
        return mock_resp

    def test_username(self):
        assert_equals(self.client.username, 'testuser')

    @patch('cerberus.user_auth.UserAuth.get_auth')
    def test_get_token(self, mock_get_auth):
        mock_get_auth.return_value = {
                                   "status": "success",
                                   "data": {
                                       "client_token": {
                                           "client_token": "7f6808f1-ede3-2177-aa9d-45f507391310",
                                       }
                                     }
                                   }
        token = self.client.get_token()
        assert_equals(token, '7f6808f1-ede3-2177-aa9d-45f507391310')

    @patch('requests.get')
    def test_get_auth(self, mock_get):
        # mock return response
        mock_resp = self._mock_response(text=self.auth_resp)
        mock_get.return_value = mock_resp
        response = self.client.get_auth()

        # confirm response matches the mock
        assert_dict_equal(response, json.loads(self.auth_resp))

    @patch('builtins.input', return_value='0987654321')
    @patch('requests.post')
    def test_mfa_response(self,mock_post,mock_input):
        mfa_data = """{
                      "status" : "success",
                      "data" : {
                        "user_id" : "134",
                        "username" : "unicorn@rainbow.com",
                        "state_token" : null,
                        "devices" : [ ],
                        "client_token" : {
                          "client_token" : "61e3-f3f-6536-a3e6-b498161d",
                          "policies" : [ "cloud-events-owner", "pixie-dust-owner"],
                          "metadata" : {
                            "groups" : "Rainbow.Playgroun.User,CareBear.users",
                            "is_admin" : "false",
                            "username" : "unicorn@rainbow.com"
                          },
                          "lease_duration" : 3600,
                          "renewable" : true
                        }
                      }
                    }"""
        # mock all the things
        mock_post.return_value = Mock()
        mock_post.return_value.status_code = 200
        mock_post.return_value.text = mfa_data

        response = self.client.get_mfa(json.loads(self.auth_resp))

        # confirm the json matches
        assert_dict_equal(response, json.loads(mfa_data))

        @raises(HTTPError)
        @patch('requests.get')
        def test_when_not_200_status_code(self, mock_get):
            mock_resp = self._mock_response(status=404, raise_for_status=HTTPError("google is down"))
            mock_get.return_value = mock_resp
            self.client.get_auth()
