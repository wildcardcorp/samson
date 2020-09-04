from samson.block_ciphers.modes.ctr import CTR
from samson.utilities.bytes import Bytes
from samson.macs.cbc_mac import CBCMAC
from samson.core.primitives import EncryptionAlg, StreamingBlockCipherMode, Primitive, AuthenticatedCipher
from samson.core.metadata import FrequencyType, SizeType, SizeSpec, EphemeralType, EphemeralSpec
from samson.ace.decorators import register_primitive

@register_primitive()
class CCM(StreamingBlockCipherMode, AuthenticatedCipher):
    """
    Counter with CBC-MAC block cipher mode.

    CCM is only defined for ciphers with 128 bit block size.
    """

    USAGE_FREQUENCY = FrequencyType.UNUSUAL
    AUTH_TAG_SIZE   = SizeSpec(size_type=SizeType.RANGE, sizes=range(32, 129, 16), typical=[128])
    EPHEMERAL       = EphemeralSpec(ephemeral_type=EphemeralType.NONCE, size=SizeSpec(size_type=SizeType.RANGE, sizes=range(8, 97, 8), typical=[96]))

    def __init__(self, cipher: EncryptionAlg, mac_len: int):
        """
        Parameters:
            cipher (EncryptionAlg): Instantiated encryption algorithm.
            mac_len          (int): Length of MAC to generate.
        """
        Primitive.__init__(self)
        self.cipher  = cipher
        self.cmac    = CBCMAC(self.cipher)
        self.mac_len = mac_len

        self.ctr = CTR(self.cipher, b'\x00' * 16)



    def _calculate_formatting_params(self, nonce: bytes, plaintext: bytes, data: bytes):
        data_len = len(data)
        q        = 15 - len(nonce)
        flags    = (64 * (data_len > 0)) + 8 * (((self.mac_len) - 2) // 2) + (q - 1)
        b_0      = Bytes(flags) + nonce + int.to_bytes(len(plaintext), q, 'big')

        return data_len, q, flags, b_0


    # https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38c.pdf
    def _generate_mac(self, nonce: bytes, plaintext: bytes, data: bytes) -> bytes:
        data_len, _q, _flags, b_0 = self._calculate_formatting_params(nonce, plaintext, data)

        data_len_encoded = b''
        if data_len > 0:
            if data_len < ((2 ** 16) - (2 ** 8)):
                size = 2

            elif data_len < (2 ** 32):
                data_len_encoded = b'\xFF\xFE'
                size = 4

            else:
                data_len_encoded = b'\xFF\xFF'
                size = 8

            data_len_encoded += int.to_bytes(data_len, size, 'big')

        padded_data = Bytes.wrap(data_len_encoded + data).pad_congruent_right(16)
        padded_plaintext = Bytes.wrap(plaintext).pad_congruent_right(16)

        T = self.cmac.generate(b_0 + padded_data + padded_plaintext, pad=False)
        return T


    def _generate_keystream(self, nonce: bytes, q: int, length: int) -> Bytes:
        formatted_nonce  = Bytes(q - 1) + nonce
        self.ctr.nonce   = formatted_nonce
        self.ctr.counter = 0
        keystream = self.ctr.encrypt(Bytes(b'').zfill(length))

        return keystream



    def encrypt(self, nonce: bytes, plaintext: bytes, data: bytes) -> Bytes:
        """
        Encrypts `plaintext`.

        Parameters:
            nonce     (bytes): Bytes-like nonce.
            plaintext (bytes): Bytes-like object to be encrypted.
            data      (bytes): Bytes-like additional data to be authenticated but not encrypted.

        Returns:
            Bytes: Resulting ciphertext.
        """
        T = self._generate_mac(nonce, plaintext, data)
        _data_len, q, _flags, _b_0 = self._calculate_formatting_params(nonce, plaintext, data)

        keystream = self._generate_keystream(nonce, q, len(plaintext) + 16)
        return (keystream[len(T):] ^ (plaintext)) + (T ^ keystream[:len(T)])[:self.mac_len]



    def decrypt(self, nonce: bytes, ciphertext: bytes, data: bytes) -> Bytes:
        """
        Decrypts `ciphertext`.

        Parameters:
            nonce     (bytes): Bytes-like nonce.
            plaintext (bytes): Bytes-like object to be decrypted.
            data      (bytes): Bytes-like additional data to be authenticated.

        Returns:
            Bytes: Resulting plaintext.
        """
        _data_len, q, _flags, _b_0 = self._calculate_formatting_params(nonce, ciphertext, data)

        keystream = self._generate_keystream(nonce, q, len(ciphertext) + (16 - self.mac_len))

        total_plaintext = (keystream[16:] + keystream[:self.mac_len]) ^ ciphertext
        plaintext, mac  = total_plaintext[:-self.mac_len], total_plaintext[-self.mac_len:]

        T = self._generate_mac(nonce, plaintext, data)[:self.mac_len]

        self.verify_tag(T, mac)

        return plaintext
