from samson.public_key.rsa import RSA
from samson.padding.pkcs1v15_padding import PKCS1v15Padding
from samson.encoding.general import bytes_to_der_sequence
from samson.encoding.asn1 import HASH_OID_LOOKUP, INVERSE_HASH_OID_LOOKUP
from samson.utilities.bytes import Bytes
from pyasn1.type.univ import Sequence, OctetString, Null
from pyasn1.codec.der import encoder

class PKCS1v15RSASigner(object):
    """
    PKCS1v15 RSA Signing and Padding Scheme
    https://tools.ietf.org/html/rfc3447#section-8.2.1
    """

    def __init__(self, rsa: RSA, hash_obj: object):
        """
        Parameters:
            rsa            (RSA): RSA object.
            hash_object (object): Object satisfying the hash interface.
        """
        self.rsa      = rsa
        self.padder   = PKCS1v15Padding(rsa.bits, block_type=1)
        self.hash_obj = hash_obj


    def sign(self, plaintext: bytes) -> Bytes:
        """
        Signs the `plaintext`.

        Parameters:
            plaintext (bytes): Plaintext to sign.
        
        Returns:
            Bytes: Signature.
        """
        alg_id = Sequence()
        alg_id.setComponentByPosition(0, HASH_OID_LOOKUP[type(self.hash_obj)])
        alg_id.setComponentByPosition(1, Null())

        top_seq = Sequence()
        top_seq.setComponentByPosition(0, alg_id)
        top_seq.setComponentByPosition(1, OctetString(self.hash_obj.hash(plaintext)))

        der_encoded = encoder.encode(top_seq)
        return self.rsa.decrypt(self.padder.pad(der_encoded)).zfill((self.rsa.n.bit_length() + 7) // 8)


    def verify(self, plaintext: bytes, signature: bytes, strict_type_match: bool=True) -> bool:
        """
        Verifies the `plaintext` against the `signature`.

        Parameters:
            plaintext        (bytes): Plaintext to verify.
            signature        (bytes): Signature to verify plaintext against.
            strict_type_match (bool): Whether or not to force use of `hash_obj` vs using the OID provided in the signature.
        
        Returns:
            bool: Whether or not the signature passed verification.
        """
        try:
            padded      = Bytes(self.rsa.encrypt(signature))
            der_encoded = self.padder.unpad(padded)

            items    = bytes_to_der_sequence(der_encoded)
            hash_obj = self.hash_obj

            if not strict_type_match:
                hash_obj = INVERSE_HASH_OID_LOOKUP[items[0][0]]()

            hashed_value = Bytes(items[1])

            # TODO: constant time?
            return hashed_value == hash_obj.hash(plaintext)
        except Exception as _:
            return False
