from samson.utilities.bytes import Bytes
from samson.core.primitives import MAC, Primitive
from samson.core.metadata import FrequencyType
from samson.ace.decorators import register_primitive

# https://en.wikipedia.org/wiki/HMAC
@register_primitive()
class HMAC(MAC):
    """
    Hash-based message authentication code using a generic interface to hash functions.
    """

    USAGE_FREQUENCY = FrequencyType.PROLIFIC

    def __init__(self, key: bytes, hash_obj: 'Hash'):
        """
        Parameters:
            key     (bytes): Bytes-like object to key the HMAC.
            hash_obj (Hash): Instantiated object with compatible hash interface.
        """
        Primitive.__init__(self)

        self.key = Bytes.wrap(key)
        self.hash_obj = hash_obj

        key_prime = self.key
        if len(self.key) > self.hash_obj.block_size:
            key_prime = self.hash_obj.hash(self.key)

        self.key_prime = key_prime + b'\x00' * (self.hash_obj.block_size - len(key_prime))
        self.outer_key_pad = self.key_prime ^ Bytes(b'\x5c').stretch(self.hash_obj.block_size)
        self.inner_key_pad = self.key_prime ^ Bytes(b'\x36').stretch(self.hash_obj.block_size)


    def __reprdir__(self):
        return ['key', 'key_prime', 'outer_key_pad', 'inner_key_pad']


    def generate(self, message: bytes) -> Bytes:
        """
        Generates a keyed MAC for `message`.

        Parameters:
            message (bytes): Message to generate a MAC for.
        
        Returns:
            Bytes: The MAC.
        """
        return self.hash_obj.hash(self.outer_key_pad + self.hash_obj.hash(self.inner_key_pad + Bytes.wrap(message)))
