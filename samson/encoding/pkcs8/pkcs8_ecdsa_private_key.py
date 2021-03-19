from samson.encoding.general import bytes_to_der_sequence
from samson.encoding.pkcs8.pkcs8_base import PKCS8Base
from samson.encoding.pkcs1.pkcs1_ecdsa_private_key import PublicPoint
from samson.encoding.x509.x509_ecdsa_params import X509ECDSAParams
from samson.utilities.bytes import Bytes
from samson.math.algebra.curves.named import WS_OID_LOOKUP
from pyasn1.type.univ import Integer, ObjectIdentifier, Sequence, SequenceOf, OctetString
from pyasn1.codec.der import encoder, decoder
from pyasn1.codec.ber import decoder as ber_decoder, encoder as ber_encoder
from pyasn1.error import PyAsn1Error
import math

class PKCS8ECDSAPrivateKey(PKCS8Base):

    @staticmethod
    def check(buffer: bytes, **kwargs) -> bool:
        try:
            items = bytes_to_der_sequence(buffer)
            return len(items) == 3 and str(items[1][0]) == '1.2.840.10045.2.1'
        except PyAsn1Error:
            return False



    def encode(self, **kwargs) -> bytes:
        alg_id = SequenceOf()
        alg_id.setComponentByPosition(0, ObjectIdentifier([1, 2, 840, 10045, 2, 1]))
        alg_id.setComponentByPosition(1, X509ECDSAParams.encode(self.key))

        zero_fill = math.ceil(self.key.G.curve.order().bit_length() / 8)

        params_seq = Sequence()
        params_seq.setComponentByPosition(0, Integer(1))
        params_seq.setComponentByPosition(1, OctetString(Bytes(self.key.d).zfill(zero_fill)))
        params_seq.setComponentByPosition(2, PublicPoint(self.key.format_public_point()))

        param_oct = OctetString(encoder.encode(params_seq))

        top_seq = Sequence()
        top_seq.setComponentByPosition(0, Integer(0))
        top_seq.setComponentByPosition(1, alg_id)
        top_seq.setComponentByPosition(2, param_oct)

        encoded = encoder.encode(top_seq)
        encoded = PKCS8ECDSAPrivateKey.transport_encode(encoded, **kwargs)
        return encoded


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'ECDSA':
        from samson.public_key.ecdsa import ECDSA
        items = bytes_to_der_sequence(buffer)

        params, _ = decoder.decode(bytes(items[2]))
        ecdsa     = X509ECDSAParams.decode(items[1][1], params[2])
        d         = Bytes(params[1]).int()
        ecdsa.d   = d
        return PKCS8ECDSAPrivateKey(ecdsa)
