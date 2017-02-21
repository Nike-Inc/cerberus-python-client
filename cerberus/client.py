import base64
import json
import requests
import sys
import boto3

from .user_auth import UserAuth

class CerberusClient(object):
    HEADERS = {"Content-Type": "application/json"}

    def __init__(self, cerberus_url, username=None, password=None):
        self.cerberus_url = cerberus_url
        self.username = username or ""
        self.password = password or ""
        # aws creds
        self.account_id = None
        self.role_name = None
        self.region = None
        self.token = None
        self.set_token()

    def set_token(self):
        if self.username:
            ua = UserAuth(self.cerberus_url, self.username, self.password)
            self.token =  ua.get_token()
        else:
            self.set_aws_auth()
            self.token =  self.get_iam_role_token()
     #   elif self.account_id is not None:
     #       return self.get_iam_role_token()
     #   else:
     #       print("ERROR: No auth set")
     #       sys.exit(2)

    def get_token(self):
        """Returns a client token from Cerberus"""
        return self.token

    def set_aws_auth(self):
        """Sets the variables needed for AWS Auth"""
        boto = boto3.client('sts')
        self.account_id = boto.get_caller_identity().get('Account')
        self.role_name = boto.get_caller_identity().get('Arn').split('/')[1]
        # get the region - couldn't figure out how to do this with boto3
        response = requests.get('http://169.254.169.254/latest/dynamic/instance-identity/document')
        self.region = json.loads(response.text)['region']

    def get_iam_role_token(self):
        """Returns a clinet token from Cerberus"""
        request_body = {
            'account_id': self.account_id,
            'role_name': self.role_name,
            'region': self.region
        }

        encrypted_resp = requests.post(self.cerberus_url + '/v1/auth/iam-role',
                                        data=json.dumps(request_body))
        encrypted_resp_json = json.loads(encrypted_resp.text)
        if encrypted_resp.status_code != 200:
           encrypted_resp.raise_for_status()

        auth_data = encrypted_resp_json['auth_data']

        client = boto3.client('kms', region_name=self.region)

        response = client.decrypt(
            CiphertextBlob=base64.decodebytes(bytes(auth_data, 'utf-8'))
        )

        token = json.loads( response['Plaintext'].decode('utf-8'))['client_token']
        return token


    def get_sdb_path(self,sdb):
        """Returns the path for a SDB"""
        id = self.get_sdb_id(sdb)
        sdb_resp = requests.get(self.cerberus_url + '/v1/safe-deposit-box/' + id + '/',
                                headers={'Content-Type' : 'application/json', 'X-Vault-Token': self.token})
        sdb_resp_json = json.loads(sdb_resp.text)
        if sdb_resp.status_code != 200:
            sdb_resp.raise_for_status()
        path = sdb_resp_json['path']
        return path

    def get_sdb_keys(self,path):
        """Returns the keys for a SDB, which are need for the full vault path"""
        list_resp = requests.get(self.cerberus_url + '/v1/secret/' + path + '/?list=true',
                                headers= {'Content-Type' : 'application/json', 'X-Vault-Token': self.token})
        list_resp_json = json.loads(list_resp.text)
        if list_resp.status_code != 200:
            list_resp.raise_for_status()
        return list_resp_json['data']['keys']

    def get_sdb_id(self,sdb):
        """ Return the ID for the given safety deposit box"""
        sdb_resp = requests.get(self.cerberus_url + '/v1/safe-deposit-box',
                                headers= {'Content-Type' : 'application/json', 'X-Vault-Token': self.token})
        sdb_resp_json = json.loads(sdb_resp.text)
        if sdb_resp.status_code != 200:
            sdb_resp.raise_for_status()
        for r in sdb_resp_json:
            if r['name'] == sdb:
                return str(r['id'])
        print("ERROR: " + sdb + " not found")
        sys.exit(2)


    def get_secret(self,vault_path,key):
        """Returs the secret based on the vault_path and key"""
        secret_resp = requests.get(self.cerberus_url + '/v1/secret/' + vault_path,
                                      headers={'Content-Type' : 'application/json', 'X-Vault-Token': self.token})
        secret_resp_json = json.loads(secret_resp.text)
        if secret_resp.status_code != 200:
          secret_resp.raise_for_status()
        if key in secret_resp_json['data']:
          return secret_resp_json['data'][key]
        else:
          print("ERROR: key " + key + " not found")
          sys.exit(2)
