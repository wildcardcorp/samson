from samson.padding.pkcs1v15_padding import PKCS1v15Padding
from samson.encoding.general import bytes_to_der_sequence
from samson.encoding.asn1 import HASH_OID_LOOKUP, INVERSE_HASH_OID_LOOKUP
from samson.utilities.bytes import Bytes
from pyasn1.type.univ import Sequence, OctetString, Null
from pyasn1.codec.der import encoder

class PKCS1v15RSASigner(object):
    def __init__(self, rsa, hash_obj):
        self.rsa = rsa
        self.padder = PKCS1v15Padding(rsa.bits, block_type=1)
        self.hash_obj = hash_obj


    def sign(self, plaintext):
        alg_id = Sequence()
        alg_id.setComponentByPosition(0, HASH_OID_LOOKUP[type(self.hash_obj)])
        alg_id.setComponentByPosition(1, Null())

        top_seq = Sequence()
        top_seq.setComponentByPosition(0, alg_id)
        top_seq.setComponentByPosition(1, OctetString(self.hash_obj.hash(plaintext)))

        der_encoded = encoder.encode(top_seq)
        return self.rsa.decrypt(self.padder.pad(der_encoded))


    def verify(self, plaintext, signature, strict_type_match=True):
        try:
            padded = Bytes(self.rsa.encrypt(signature))
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
