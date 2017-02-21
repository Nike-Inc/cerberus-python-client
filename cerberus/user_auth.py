import requests
import json

class UserAuth(object):
    """Class to authenicate with username and password and returns vault token"""
    HEADERS = {"Content-Type": "application/json"}

    def __init__(self, cerberus_url, username, password):
        self.cerberus_url = cerberus_url
        self.username = username
        self.password = password

    def get_auth(self):
        """Returns auth respose which has client token unless MFA is required"""
        auth_resp = requests.get(self.cerberus_url + '/v2/auth/user',
                                 auth=(self.username, self.password))
        auth_resp_json = json.loads(auth_resp.text)
        if auth_resp.status_code != 200:
           auth_resp.raise_for_status()
        return auth_resp_json

    def get_token(self):
      """sets client token from Cerberus"""
      auth_resp = self.get_auth()
      if auth_resp['status'] == 'mfa_req':
        token_resp = self.get_mfa(auth_resp)
      else:
        token_resp = auth_resp
      token = token_resp['data']['client_token']['client_token']
      return token

    def get_mfa(self, auth_resp):
        """Gets MFA code from user and returns response which includes the client token"""
        # TODO check if there is more than 1 device.
        # currently cerberus only support Google Authenicator
        sec_code = input('Enter ' + auth_resp['data']['devices'][0]['name'] + ' security code: ')
        mfa_resp = requests.post(self.cerberus_url + '/v2/auth/mfa_check',
                                json={'otp_token': sec_code,
                                      'device_id': auth_resp['data']['devices'][0]['id'],
                                      'state_token': auth_resp['data']['state_token']},
                                       headers=self.HEADERS)
        mfa_resp_json = json.loads(mfa_resp.text)
        if mfa_resp.status_code != 200:
            mfa_resp.raise_for_status()
        return mfa_resp_json
