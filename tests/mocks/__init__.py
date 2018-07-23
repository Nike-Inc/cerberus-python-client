import requests

class MultiEndpointRequest(object):
    """ A requests.get mock that returns different results for different endpoints and raises ConnectionError if
    the endpoint isn't set"""
    def __init__(self, dict):
        self.dict = dict

    def get(self, url):
        try:
            return self.dict[url]
        except KeyError:
            raise requests.exceptions.ConnectionError