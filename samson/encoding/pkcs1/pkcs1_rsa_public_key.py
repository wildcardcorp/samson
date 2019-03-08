from samson.encoding.general import export_der, bytes_to_der_sequence

class PKCS1RSAPublicKey(object):
    @staticmethod
    def check(buffer: bytes):
        items = bytes_to_der_sequence(buffer)
        return len(items) == 2

    @staticmethod
    def encode(rsa_key: object):
        encoded = export_der([rsa_key.n, rsa_key.e])
        return encoded


    @staticmethod
    def decode(buffer: bytes):
        from samson.public_key.rsa import RSA
        items = bytes_to_der_sequence(buffer)
        print(items)

        items = [int(item) for item in items]

        n, e = items

        rsa = RSA(8, e=e)
        rsa.n = n
        rsa.bits = rsa.n.bit_length()

        return rsa
