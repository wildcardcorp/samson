from samson.utilities.bytes import Bytes

# https://en.wikipedia.org/wiki/Disk_encryption_theory#Xor%E2%80%93encrypt%E2%80%93xor_(XEX)
# This is basically XEX with conditional CTS. Padding the plaintext to the 16-byte boundary
# should, therefore, result in a correct execution of XEX.
class XTS(object):
    def __init__(self, encryptor, decryptor, sector_encryptor):
        self.encryptor = encryptor
        self.decryptor = decryptor
        self.sector_encryptor = sector_encryptor

    

    def __repr__(self):
        return f"<XTS: encryptor={self.encryptor}, decryptor={self.decryptor}, sector_encryptor={self.sector_encryptor}>"

    def __str__(self):
        return self.__repr__()



    def _xts(self, in_bytes, i, func, reverse_cts=False):
        in_bytes = Bytes.wrap(in_bytes)
        i_bytes = Bytes(i)

        X = self.sector_encryptor(i_bytes + b'\x00' * (16 - len(i_bytes)))[::-1].int()
        
        out_bytes = Bytes(b'')
        byte_chunks = in_bytes.chunk(16, allow_partials=True)

        for block in byte_chunks:
            if len(block) == 16:
                if X >> 128:
                    X ^= 0x100000000000000000000000000000087

                X = Bytes(X, 'little').zfill(16)
                out_bytes += func(block ^ X) ^ X

                X = X.int()
                X <<= 1
            else:
                curr_X = X
                if X >> 128:
                    X ^= 0x100000000000000000000000000000087

                # Decryption needs to reverse the ordering of the X's.
                # Here I just throw out the last block, use the most recent X,
                # and then backpedal X.
                if reverse_cts:
                    out_bytes = out_bytes[:-16]
                    X = Bytes(X, 'little').zfill(16)
                    last_chunk = func(byte_chunks[-2] ^ X) ^ X
                    X = curr_X >> 1
                else:
                    out_bytes, last_chunk = out_bytes[:-16], out_bytes[-16:]
                
                stolen, left_over = last_chunk[len(block):], last_chunk[:len(block)]
                padded_block = block + stolen
                X = Bytes(X, 'little').zfill(16)
                out_bytes += (func(padded_block ^ X) ^ X) + left_over
                

        return out_bytes
    


    def encrypt(self, plaintext, i):
        return self._xts(plaintext, i, self.encryptor, reverse_cts=False)


    def decrypt(self, ciphertext, i):
        return self._xts(ciphertext, i, self.decryptor, reverse_cts=True)