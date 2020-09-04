from samson.hashes.md4 import MD4
from samson.utilities.bytes import Bytes
from samson.core.base_object import BaseObject

class NTLM(BaseObject):
    def __init__(self):
        self.md4        = MD4()
        self.block_size = self.md4.block_size


    def hash(self, message: bytes) -> Bytes:
        """
        Hash `message` with NTLM.

        Parameters:
            message (bytes): Message to be hashed.
        
        Returns:
            Bytes: NTLM hash.
        """
        return self.md4.hash(message.decode().encode('utf-16le'))
