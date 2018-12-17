from samson.block_ciphers.modes.cbc import CBC
from samson.utilities.bytes import Bytes
from samson.block_ciphers.rijndael import Rijndael

class CBCMAC(object):
    """
    Message authentication code scheme based off of a block cipher in CBC mode.
    """

    def __init__(self, key: bytes, cipher: Rijndael, iv: bytes=b'\x00' * 16):
        """
        Parameters:
            key    (bytes): Bytes-like object to key the underlying cipher.
            cipher (class): Instantiable class representing a block cipher.
            iv     (bytes): Initialization vector for CBC mode.
        """
        self.key = key
        self.iv = iv
        self.cipher = cipher


    def __repr__(self):
        return f"<CBCMAC: key={self.key}, iv={self.iv}, cipher={self.cipher}>"


    def __str__(self):
        return self.__repr__()


    def generate(self, message: bytes, pad: bool=True) -> Bytes:
        """
        Generates a keyed MAC for `message`.

        Parameters:
            message (bytes): Message to generate a MAC for.
            pad      (bool): Whether or not to pad the message with PKCS7.
        
        Returns:
            Bytes: The MAC.
        """
        cryptor = self.cipher(self.key)
        cbc = CBC(cryptor.encrypt, cryptor.decrypt, self.iv, cryptor.block_size)
        return cbc.encrypt(message, pad)[-(cryptor.block_size):]
