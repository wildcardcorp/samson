from samson.encoding.pem import PEMEncodable

class PKCS8Base(PEMEncodable):
    DEFAULT_MARKER = 'PRIVATE KEY'
    DEFAULT_PEM = True
    USE_RFC_4716 = False
