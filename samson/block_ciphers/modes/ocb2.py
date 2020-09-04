from samson.utilities.bytes import Bytes
from samson.kdfs.s2v import dbl
from samson.core.primitives import EncryptionAlg, StreamingBlockCipherMode, Primitive, AuthenticatedCipher
from samson.core.metadata import SizeType, SizeSpec, EphemeralType, EphemeralSpec
from samson.ace.decorators import register_primitive

def triple(bytestring):
    return bytestring ^ dbl(bytestring)


@register_primitive()
class OCB2(StreamingBlockCipherMode, AuthenticatedCipher):
    """
    Offset codebook version 2 block cipher mode.
    http://web.cs.ucdavis.edu/~rogaway/papers/draft-krovetz-ocb-00.txt
    """

    EPHEMERAL     = EphemeralSpec(ephemeral_type=EphemeralType.NONCE, size=SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda block_mode: block_mode.cipher.BLOCK_SIZE, typical=[128]))
    AUTH_TAG_SIZE = SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda block_mode: block_mode.cipher.BLOCK_SIZE, typical=[128])

    def __init__(self, cipher: EncryptionAlg):
        """
        Parameters:
            cipher (EncryptionAlg): Instantiated encryption algorithm.
        """
        Primitive.__init__(self)
        self.cipher = cipher


    # TODO: We already have a PMAC class, but it doesn't seem to produce
    # the same results. Is there some trivial tweak we can do so we don't
    # have to have two implementations?
    def internal_pmac(self, data):
        data = Bytes.wrap(data)

        data_chunks = data.chunk(self.cipher.block_size, allow_partials=True)

        offset = self.cipher.encrypt(Bytes(b'').zfill(self.cipher.block_size))
        offset = triple(offset)
        offset = triple(offset)

        checksum = Bytes(b'').zfill(self.cipher.block_size)

        for i in range(len(data_chunks) - 1):
            offset = dbl(offset)
            checksum ^= self.cipher.encrypt(offset ^ data_chunks[i])

        offset = dbl(offset)

        M_last = data_chunks[-1]

        if len(M_last) % self.cipher.block_size == 0:
            offset = triple(offset)
            checksum ^= M_last
        else:
            M_last += b'\x80'
            M_last  = (M_last + (b'\x00' * (self.cipher.block_size - len(M_last))))

            checksum ^= M_last
            offset = triple(offset)
            offset = triple(offset)

        return self.cipher.encrypt(offset ^ checksum)



    def encrypt(self, nonce: bytes, plaintext: bytes, auth_data: bytes=None) -> (Bytes, Bytes):
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext (bytes): Bytes-like object to be encrypted.
        
        Returns:
            Bytes: Resulting ciphertext.
        """
        plaintext = Bytes.wrap(plaintext)

        message_chunks = plaintext.chunk(self.cipher.block_size, allow_partials=True)
        offset = self.cipher.encrypt(nonce)
        checksum = Bytes(b'').zfill(self.cipher.block_size)

        if not message_chunks:
            message_chunks = [plaintext]

        ciphertext = Bytes(b'')

        for i in range(len(message_chunks) - 1):
            offset = dbl(offset)
            checksum ^= message_chunks[i]
            xoffset = self.cipher.encrypt(offset ^ message_chunks[i])
            ciphertext += offset ^ xoffset

        offset = dbl(offset)

        M_last   = message_chunks[-1]
        last_len = len(M_last)
        padding  = self.cipher.encrypt(Bytes(last_len * 8).zfill(self.cipher.block_size) ^ offset)

        ciphertext += M_last ^ padding[:last_len]
        checksum   ^= M_last + padding[last_len:]

        offset = triple(offset)
        tag    = self.cipher.encrypt(checksum ^ offset)

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

        message_chunks = ciphertext.chunk(self.cipher.block_size, allow_partials=True)
        offset   = self.cipher.encrypt(nonce)
        checksum = Bytes(b'').zfill(self.cipher.block_size)

        if not message_chunks:
            message_chunks = [ciphertext]

        plaintext = Bytes(b'')

        for i in range(len(message_chunks) - 1):
            offset     = dbl(offset)
            pt_chunk   = self.cipher.decrypt(offset ^ message_chunks[i]) ^ offset
            checksum  ^= pt_chunk
            plaintext += pt_chunk

        offset  = dbl(offset)

        M_last   = message_chunks[-1]
        last_len = len(M_last)
        padding  = self.cipher.encrypt(Bytes(last_len * 8).zfill(self.cipher.block_size) ^ offset)

        M_last    ^= padding[:last_len]
        plaintext += M_last
        checksum  ^= M_last + padding[last_len:]

        offset = triple(offset)
        tag    = self.cipher.encrypt(checksum ^ offset)

        if auth_data:
            tag ^= self.internal_pmac(auth_data)


        if verify:
            self.verify_tag(tag, given_tag)

        return plaintext
