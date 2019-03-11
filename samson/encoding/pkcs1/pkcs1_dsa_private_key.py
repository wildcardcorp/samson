from samson.encoding.general import export_der, bytes_to_der_sequence

class PKCS1DSAPrivateKey(object):
    """
    Not in the RFC spec, but OpenSSL supports it.
    """

    DEFAULT_MARKER = 'DSA PRIVATE KEY'
    DEFAULT_PEM = True

    @staticmethod
    def check(buffer: bytes):
        items = bytes_to_der_sequence(buffer)
        return len(items) == 6 and int(items[0]) == 0


    @staticmethod
    def encode(dsa_key: object):
        encoded = export_der([0, dsa_key.p, dsa_key.q, dsa_key.g, dsa_key.y, dsa_key.x])
        return encoded


    @staticmethod
    def decode(buffer: bytes):
        from samson.public_key.dsa import DSA
        items = bytes_to_der_sequence(buffer)

        p, q, g, y, x = [int(item) for item in items[1:6]]
        dsa = DSA(None, p=p, q=q, g=g, x=x)
        dsa.y = y

        return dsa
