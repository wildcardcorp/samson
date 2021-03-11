from samson.utilities.bytes import Bytes
from samson.core.primitives import MAC, Primitive
from samson.core.metadata import FrequencyType
from samson.ace.decorators import register_primitive
from samson.hashes.sha3 import cSHAKE128, cSHAKE256

class KMAC(MAC):
    USAGE_FREQUENCY = FrequencyType.UNUSUAL

    def __init__(self, key: bytes, cSHAKE: type, digest_bit_length: int, customization_str: bytes=b''):
        """
        Parameters:
            key               (bytes): Bytes-like object to key the HMAC.
            cSHAKE             (type): cSHAKE class to use.
            digest_bit_size     (int): Desired size of output.
            customization_str (bytes): User defined string.
        """
        self.hash_obj = cSHAKE(
            digest_bit_length=digest_bit_length,
            function_name=b'KMAC',
            customization_str=customization_str
        )

        self.key = key
        self.padded_key = self.hash_obj.bytepad(self.hash_obj.encode_string(self.key))


    def __reprdir__(self):
        return ['key', 'hash_obj']


    def generate(self, message: bytes) -> Bytes:
        """
        Generates a keyed MAC for `message`.

        Parameters:
            message (bytes): Message to generate a MAC for.

        Returns:
            Bytes: The MAC.
        """
        new_x = self.padded_key + Bytes.wrap(message) + self.hash_obj.right_encode(self.hash_obj.digest_size*8)
        return self.hash_obj.hash(new_x)



@register_primitive()
class KMAC128(KMAC):
    def __init__(self, key: bytes, digest_bit_length: int, customization_str: bytes=b''):
        """
        Parameters:
            key               (bytes): Bytes-like object to key the HMAC.
            digest_bit_size     (int): Desired size of output.
            customization_str (bytes): User defined string.
        """
        super().__init__(key=key, cSHAKE=cSHAKE128, digest_bit_length=digest_bit_length, customization_str=customization_str)
        Primitive.__init__(self)


@register_primitive()
class KMAC256(KMAC):
    def __init__(self, key: bytes, digest_bit_length: int, customization_str: bytes=b''):
        """
        Parameters:
            key               (bytes): Bytes-like object to key the HMAC.
            digest_bit_size     (int): Desired size of output.
            customization_str (bytes): User defined string.
        """
        super().__init__(key=key, cSHAKE=cSHAKE256, digest_bit_length=digest_bit_length, customization_str=customization_str)
        Primitive.__init__(self)
