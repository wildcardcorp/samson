from samson.block_ciphers.modes.ctr import CTR
from samson.utilities.bytes import Bytes
from samson.macs.cbc_mac import CBCMAC
import hmac


class CCM(object):
    """Counter with CBC-MAC block cipher mode."""

    def __init__(self, key: bytes, cipher: object, mac_len: int):
        self.key = key
        self.cipher = cipher
        self.cmac = CBCMAC(self.key, self.cipher)
        self.mac_len = mac_len

        self.enc_obj = self.cipher(key)
        self.ctr = CTR(self.enc_obj.encrypt, b'\x00' * 16, 16)


    def __repr__(self):
        return f"<CCM: enc_obj={self.enc_obj}, key={self.key}, ctr={self.ctr}>"


    def __str__(self):
        return self.__repr__()


    def _calculate_formattting_params(self, nonce: bytes, plaintext: bytes, data: bytes):
        data_len = len(data)
        q = 15 - len(nonce)
        flags = (64 * (data_len > 0)) + 8 * (((self.mac_len) - 2) // 2) + (q - 1)
        b_0 = Bytes(flags) + nonce + int.to_bytes(len(plaintext), q, 'big')

        return data_len, q, flags, b_0


    def _pad_to_16(self, in_bytes: bytes) -> bytes:
        return in_bytes + (b'\x00' * ((16 - (len(in_bytes) % 16)) % 16))


    # https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38c.pdf
    def _generate_mac(self, nonce: bytes, plaintext: bytes, data: bytes) -> bytes:
        data_len, _q, _flags, b_0 = self._calculate_formattting_params(nonce, plaintext, data)

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

        padded_data = self._pad_to_16(data_len_encoded + data)
        padded_plaintext = self._pad_to_16(plaintext)

        T = self.cmac.generate(b_0 + padded_data + padded_plaintext, pad=False)
        return T


    def _generate_keystream(self, nonce: bytes, q: int, length: int) -> Bytes:
        formatted_nonce = Bytes(q - 1) + nonce
        self.ctr.nonce = formatted_nonce
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
        _data_len, q, _flags, _b_0 = self._calculate_formattting_params(nonce, plaintext, data)

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
        _data_len, q, _flags, _b_0 = self._calculate_formattting_params(nonce, ciphertext, data)

        keystream = self._generate_keystream(nonce, q, len(ciphertext) + (16 - self.mac_len))

        total_plaintext = (keystream[16:] + keystream[:self.mac_len]) ^ ciphertext
        plaintext, mac = total_plaintext[:-self.mac_len], total_plaintext[-self.mac_len:]

        T = self._generate_mac(nonce, plaintext, data)[:self.mac_len]

        if not hmac.compare_digest(T, mac):
            raise Exception("Authentication of data failed: MACs not equal")

        return plaintext
