from samson.encoding.general import bytes_to_der_sequence, HASH_OID_LOOKUP, INVERSE_HASH_OID_LOOKUP
from samson.utilities.bytes import Bytes
from pyasn1.type.univ import Integer, ObjectIdentifier, Sequence, SequenceOf, OctetString, Null
from pyasn1.codec.der import encoder, decoder
from pyasn1_modules import rfc2459


class PKCS1RSASignature(object):
    def __init__(self, signature, hash_alg):
        self.signature = signature
        self.hash_alg = hash_alg


    def encode(self):
        alg_id = rfc2459.AlgorithmIdentifier()
        alg_id['algorithm']   = ObjectIdentifier([int(item) for item in HASH_OID_LOOKUP[self.hash_alg].split('.')])
        alg_id['parameters']  = Null()

        top_seq = Sequence()
        top_seq.setComponentByPosition(0, alg_id)
        top_seq.setComponentByPosition(1, OctetString(self.signature))

        return encoder.encode(top_seq)


    @staticmethod
    def decode(buffer: bytes, **kwargs):
        from samson.public_key.rsa import RSA
        items = bytes_to_der_sequence(buffer)

        signature = Bytes(items[1])
        hash_alg = INVERSE_HASH_OID_LOOKUP[str(items[0][0])]
        return PKCS1RSASignature(signature, hash_alg)
