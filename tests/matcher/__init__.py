class AnyDictWithKey(str):
    """ Argument matcher that matches a dictionary (or other data structures) that contains the key"""
    def __eq__(self, other):
        return self in other
    def __hash__(self):
        return super(AnyDictWithKey, self).__hash__()