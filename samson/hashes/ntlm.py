from samson.hashes.md4 import MD4
from samson.utilities.bytes import Bytes

class NTLM(object):
    def __init__(self):
        self.md4        = MD4()
        self.block_size = self.md4.block_size

    def __repr__(self):
        return f"<NTLM: md4={self.md4}, block_size={self.block_size}>"

    def __str__(self):
        return self.__repr__()


    def hash(self, message: bytes) -> Bytes:
        """
        Hash `message` with NTLM.

        Parameters:
            message (bytes): Message to be hashed.
        
        Returns:
            Bytes: NTLM hash.
        """
        return self.md4.hash(message.decode().encode('utf-16le'))
