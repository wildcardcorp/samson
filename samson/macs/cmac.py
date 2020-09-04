from samson.macs.cbc_mac import CBCMAC
from samson.utilities.bytes import Bytes
from samson.block_ciphers.rijndael import Rijndael
from samson.core.primitives import MAC, Primitive, EncryptionAlg
from samson.core.metadata import FrequencyType
from samson.ace.decorators import register_primitive

@register_primitive()
class CMAC(MAC):
    """
    Message authentication code scheme based off of CBCMAC.
    """

    USAGE_FREQUENCY = FrequencyType.NORMAL

    def __init__(self, cipher: EncryptionAlg=None, iv: bytes=b'\x00' * 16):
        """
        Parameters:
            cipher (EncryptionAlg): Instantiated encryption algorithm.
            iv             (bytes): Initialization vector for CBC mode.
        """
        Primitive.__init__(self)
        self.cipher = cipher or Rijndael(Bytes.random(32))
        self.k1, self.k2 = self.generate_subkeys()
        self.cbc_mac = CBCMAC(cipher, iv)



    def __reprdir__(self):
        return ['cipher', 'k1', 'k2']


    # https://tools.ietf.org/html/rfc4493#section-2.3
    def generate_subkeys(self) -> (bytes, bytes):
        """
        Internal function used to generate CMAC subkeys `k1` and `k2`.
        """
        L = self.cipher.encrypt(Bytes(b'').zfill(self.cipher.block_size))

        if L.int() & 0x80000000000000000000000000000000:
            K1 = (L << 1) ^ 0x00000000000000000000000000000087
        else:
            K1 = L << 1

        if K1.int() & 0x80000000000000000000000000000000:
            K2 = (K1 << 1) ^ 0x00000000000000000000000000000087
        else:
            K2 = K1 << 1

        return K1, K2


    def generate(self, message: bytes) -> Bytes:
        """
        Generates a keyed MAC for `message`.

        Parameters:
            message (bytes): Message to generate a MAC for.
        
        Returns:
            Bytes: The MAC.
        """
        message = Bytes.wrap(message)

        incomplete_block = len(message) % self.cipher.block_size
        message_chunks   = message.chunk(self.cipher.block_size, allow_partials=True)

        if len(message_chunks) == 0:
            message_chunks = [Bytes(b'')]

        M_last = message_chunks[-1]

        if incomplete_block or not len(message):
            M_last += b'\x80'
            M_last  = (M_last + (b'\x00' * (self.cipher.block_size - len(M_last)))) ^ self.k2
        else:
            M_last ^= self.k1

        return self.cbc_mac.generate(b''.join(message_chunks[:-1]) + M_last, pad=False)
