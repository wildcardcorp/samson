from samson.utilities.bytes import Bytes

# https://en.wikipedia.org/wiki/HMAC
class HMAC(object):
    def __init__(self, key, hash_obj):
        self.key = Bytes.wrap(key)
        self.hash_obj = hash_obj

        key_prime = self.key
        if len(self.key) > self.hash_obj.block_size:
            key_prime = self.hash_obj.hash(self.key)

        self.key_prime = key_prime + b'\x00' * (self.hash_obj.block_size - len(key_prime))
        self.outer_key_pad = self.key_prime ^ Bytes(b'\x5c').stretch(self.hash_obj.block_size)
        self.inner_key_pad = self.key_prime ^ Bytes(b'\x36').stretch(self.hash_obj.block_size)


    def __repr__(self):
        return f"<HMAC: key={self.key}, key_prime={self.key_prime}, outer_key_pad={self.outer_key_pad}, inner_key_pad={self.inner_key_pad}>"

    def __str__(self):
        return self.__repr__()


    def generate(self, message):
        return self.hash_obj.hash(self.outer_key_pad + self.hash_obj.hash(self.inner_key_pad + message))