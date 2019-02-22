from samson.utilities.bytes import Bytes
from samson.kdfs.s2v import dbl
from types import FunctionType

def triple(bytestring):
    return bytestring ^ dbl(bytestring)


class OCB2(object):
    """
    Offset codebook version 2 block cipher mode.
    http://web.cs.ucdavis.edu/~rogaway/papers/draft-krovetz-ocb-00.txt
    """

    def __init__(self, encryptor: FunctionType, decryptor: FunctionType, block_size: int):
        """
        Parameters:
            encryptor (func): Function that takes in a plaintext and returns a ciphertext.
            decryptor (func): Function that takes in a ciphertext and returns a plaintext.
            block_size (int): Block size of the underlying encryption algorithm.
        """
        self.encryptor = encryptor
        self.decryptor = decryptor
        self.block_size = block_size


    def __repr__(self):
        return f"<OCB2: encryptor={self.encryptor}, decryptor={self.decryptor}, block_size={self.block_size}>"

    def __str__(self):
        return self.__repr__()


    # TODO: We already have a PMAC class, but it doesn't seem to produce
    # the same results. Is there some trivial tweak we can do so we don't
    # have to have two implementations?
    def internal_pmac(self, data):
        data = Bytes.wrap(data)

        data_chunks = data.chunk(self.block_size, allow_partials=True)

        offset = self.encryptor(Bytes(b'').zfill(self.block_size))
        offset = triple(offset)
        offset = triple(offset)

        checksum = Bytes(b'').zfill(self.block_size)

        for i in range(len(data_chunks) - 1):
            offset = dbl(offset)
            checksum ^= self.encryptor(offset ^ data_chunks[i])

        offset = dbl(offset)

        M_last = data_chunks[-1]

        if len(M_last) % self.block_size == 0:
            offset = triple(offset)
            checksum ^= M_last
        else:
            M_last += b'\x80'
            M_last  = (M_last + (b'\x00' * (self.block_size - len(M_last))))

            checksum ^= M_last
            offset = triple(offset)
            offset = triple(offset)

        return self.encryptor(offset ^ checksum)



    def encrypt(self, nonce: bytes, plaintext: bytes, auth_data: bytes=None) -> (Bytes, Bytes):
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext (bytes): Bytes-like object to be encrypted.
        
        Returns:
            Bytes: Resulting ciphertext.
        """
        plaintext = Bytes.wrap(plaintext)

        message_chunks = plaintext.chunk(self.block_size, allow_partials=True)
        offset = self.encryptor(nonce)
        checksum = Bytes(b'').zfill(self.block_size)

        if not message_chunks:
            message_chunks = [plaintext]

        ciphertext = Bytes(b'')

        for i in range(len(message_chunks) - 1):
            offset = dbl(offset)
            checksum ^= message_chunks[i]
            xoffset = self.encryptor(offset ^ message_chunks[i])
            ciphertext += offset ^ xoffset

        offset = dbl(offset)

        M_last = message_chunks[-1]
        last_len = len(M_last)
        padding = self.encryptor(Bytes(last_len * 8).zfill(self.block_size) ^ offset)

        ciphertext += M_last ^ padding[:last_len]
        checksum ^= M_last + padding[last_len:]

        offset = triple(offset)
        tag = self.encryptor(checksum ^ offset)

        if auth_data:
            tag ^= self.internal_pmac(auth_data)

        return tag, ciphertext



    def decrypt(self, nonce: bytes, ciphertext: bytes, auth_data: bytes=None, verify: bool=True) -> Bytes:
        """
        Decrypts `ciphertext`.

        Parameters:
            ciphertext (bytes): Bytes-like object to be decrypted.
        
        Returns:
            Bytes: Resulting plaintext.
        """
        given_tag, ciphertext = ciphertext
        ciphertext = Bytes.wrap(ciphertext)

        message_chunks = ciphertext.chunk(self.block_size, allow_partials=True)
        offset = self.encryptor(nonce)
        checksum = Bytes(b'').zfill(self.block_size)

        if not message_chunks:
            message_chunks = [ciphertext]

        plaintext = Bytes(b'')

        for i in range(len(message_chunks) - 1):
            offset = dbl(offset)
            pt_chunk = self.decryptor(offset ^ message_chunks[i]) ^ offset
            checksum ^= pt_chunk
            plaintext += pt_chunk

        offset = dbl(offset)

        M_last = message_chunks[-1]
        last_len = len(M_last)
        padding = self.encryptor(Bytes(last_len * 8).zfill(self.block_size) ^ offset)

        M_last ^= padding[:last_len]
        plaintext += M_last
        checksum ^= M_last + padding[last_len:]

        offset = triple(offset)
        tag = self.encryptor(checksum ^ offset)

        if auth_data:
            tag ^= self.internal_pmac(auth_data)


        if verify:
            assert tag == given_tag

        return plaintext
