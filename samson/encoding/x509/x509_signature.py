from samson.core.base_object import BaseObject

class X509Signature(BaseObject):
    def __init__(self, oid, hash_obj):
        self.oid      = oid
        self.hash_obj = hash_obj

    def sign(self, pki_obj, data):
        raise NotImplementedError()

    def verify(self, pki_obj, data, sig):
        raise NotImplementedError()
