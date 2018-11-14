from samson.utilities.bytes import Bytes

# https://en.wikipedia.org/wiki/Ciphertext_stealing
# CTS-3
class CBCCTS(object):
    def __init__(self, underlying_mode):
        self.underlying_mode = underlying_mode
    


    def __repr__(self):
        return f"<CBCCTS: underlying_mode={self.underlying_mode}>"

    def __str__(self):
        return self.__repr__()



    def encrypt(self, plaintext):
        plaintext = Bytes.wrap(plaintext)
        block_size = self.underlying_mode.block_size
        pt_len = len(plaintext)

        padding_len = (block_size - (pt_len % block_size)) % block_size

        ciphertext_chunks = self.underlying_mode.encrypt(plaintext + b'\x00' * (padding_len), pad=False).chunk(block_size)
        return (sum(ciphertext_chunks[:-2]) + ciphertext_chunks[-1] + ciphertext_chunks[-2])[:pt_len]



    def decrypt(self, ciphertext):
        ciphertext = Bytes.wrap(ciphertext)
        block_size = self.underlying_mode.block_size
        ct_chunks = ciphertext.chunk(block_size, allow_partials=True)
        ct_len = len(ciphertext)

        padding_len = (block_size - (ct_len % block_size)) % block_size

        D_n = self.underlying_mode.decryptor(ct_chunks[-2])
        C_n = sum(ct_chunks[:-2]) + ct_chunks[-1] + D_n[-padding_len:][:padding_len] + ct_chunks[-2]

        return self.underlying_mode.decrypt(C_n, unpad=False)[:ct_len]