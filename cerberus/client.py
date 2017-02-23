import json
import requests
import sys

# local classes
from .user_auth import UserAuth
from .aws_auth import AWSAuth

class CerberusClient(object):
    """ Cerberus Python Client for interacting with
        Cerberus APIs and Vault. Authentication is done
        via the Auth Classes"""
    HEADERS = {"Content-Type": "application/json"}

    def __init__(self, cerberus_url, username=None, password=None):
        """username and password are optional, they are not neeeded
           for IAM Role Auth"""
        self.cerberus_url = cerberus_url
        self.username = username or ""
        self.password = password or ""
        self.token = None
        self.set_token()

    def set_token(self):
        """Set the Valut token based on auth type"""
        if self.username:
            ua = UserAuth(self.cerberus_url, self.username, self.password)
            self.token =  ua.get_token()
        #if CERBERUS_TOKEN
        #   self.token = CERBERUS_TOKEN
        else:
            awsa = AWSAuth(self.cerberus_url)
            self.token =  awsa.get_token()

    def get_token(self):
        """Returns a client token from Cerberus"""
        return self.token

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
        """Returns the secret based on the vault_path and key"""
        secret_resp_json = self.get_secrets(vault_path)
        if key in secret_resp_json['data']:
          return secret_resp_json['data'][key]
        else:
          print("ERROR: key " + key + " not found")
          sys.exit(2)

    def get_secrets(self,vault_path):
        """Returns json secrets based on the vault_path"""
        secret_resp = requests.get(self.cerberus_url + '/v1/secret/' + vault_path,
                                      headers={'Content-Type' : 'application/json', 'X-Vault-Token': self.token})
        secret_resp_json = json.loads(secret_resp.text)
        if secret_resp.status_code != 200:
          secret_resp.raise_for_status()
        return secret_resp_json
