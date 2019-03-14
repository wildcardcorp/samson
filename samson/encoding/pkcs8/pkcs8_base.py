# from samson.encoding.pem import pem_encode
from samson.encoding.pem import PEMEncodable

class PKCS8Base(PEMEncodable):
    DEFAULT_MARKER = 'PRIVATE KEY'
    DEFAULT_PEM = True
    USE_RFC_4716 = False


    # @classmethod
    # def transport_encode(cls, buffer: bytes, **kwargs):
    #     if kwargs.get('encode_pem'):
    #         buffer = pem_encode(buffer, kwargs.get('marker') or cls.DEFAULT_MARKER, encryption=kwargs.get('encryption'), passphrase=kwargs.get('passphrase'), iv=kwargs.get('iv'))

    #     return buffer
