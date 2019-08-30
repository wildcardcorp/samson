from samson.block_ciphers.des import DES
from samson.utilities.bytes import Bytes

class LM(object):
    def __init__(self, plaintext: bytes=b'KGS!@#$%'):
        self.plaintext  = plaintext
        self.block_size = 7
    
    def __repr__(self):
        return f"<LM: plaintext={self.plaintext}, block_size={self.block_size}>"

    def __str__(self):
        return self.__repr__()
    

    def hash(self, message: bytes) -> Bytes:
        """
        Hash `message` with LM.

        Parameters:
            message (bytes): Message to be hashed.
        
        Returns:
            Bytes: LM hash.
        """
        key  = Bytes.wrap(message.upper())[:14]
        key += b'\x00' * (14 - len(key))

        # Add parity bits
        key_bits = key.bits()
        key      = Bytes(int(''.join([str(chunk) + '0' for chunk in key_bits.chunk(7)]), 2)).zfill(16)

        return DES(key[:8]).encrypt(self.plaintext) + DES(key[8:]).encrypt(self.plaintext)
