from samson.core.base_object import BaseObject

class X509Signature(BaseObject):
    def __init__(self, name, hash_obj):
        self.name     = name
        self.hash_obj = hash_obj

    def sign(self, pki_obj, data):
        raise NotImplementedError()

    def verify(self, pki_obj, data, sig):
        raise NotImplementedError()
