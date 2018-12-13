from samson.block_ciphers.des import DES
from samson.utilities.bytes import Bytes

class TDES(object):
    """
    3DES in EDE mode.

    Structure: Feistel Network
    Key size: 64, 128, 192 bits (56, 112, 168 bits of security)
    Block size: 64 bits
    """

    def __init__(self, key: bytes):
        """
        Parameters:
            key (bytes): Bytes-like object to key the cipher.
        """
        key = Bytes.wrap(key)
        if not len(key) in [8, 16, 24]:
            raise ValueError('`key` size must be in [8, 16, 24]')

        self.key = key
        self.des_arr = [DES(subkey.zfill(8)) for subkey in key.chunk(8)]
        self.block_size = 8



    def __repr__(self):
        return f"<TDES: key={self.key}, des_arr={self.des_arr}>"

    def __str__(self):
        return self.__repr__()


    def encrypt(self, plaintext: bytes) -> Bytes:
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext (bytes): Bytes-like object to be encrypted.
        
        Returns:
            Bytes: Resulting ciphertext.
        """
        plaintext = Bytes.wrap(plaintext)
        pt_1 = self.des_arr[0].encrypt(plaintext)
        pt_2 = self.des_arr[1].decrypt(pt_1)
        ciphertext = self.des_arr[2].encrypt(pt_2)

        return ciphertext


    def decrypt(self, ciphertext: bytes) -> Bytes:
        """
        Decrypts `ciphertext`.

        Parameters:
            ciphertext (bytes): Bytes-like object to be decrypted.
        
        Returns:
            Bytes: Resulting plaintext.
        """
        ciphertext = Bytes.wrap(ciphertext)
        ct_1 = self.des_arr[2].decrypt(ciphertext)
        ct_2 = self.des_arr[1].encrypt(ct_1)
        plaintext = self.des_arr[0].decrypt(ct_2)

        return plaintext
