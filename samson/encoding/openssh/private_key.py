from samson.encoding.openssh.literal import Literal

class PrivateKey(object):
    @staticmethod
    def check_decrypt(params, decryptor):
        if decryptor:
            params = decryptor(params)

        check_bytes, params = Literal('check_bytes', length=8).unpack(params)
        check1, check2 = check_bytes.chunk(4)

        if check1 != check2:
            raise ValueError(f'Private key check bytes incorrect. Is it encrypted? check1: {check1}, check2: {check2}')

        return check_bytes, params
