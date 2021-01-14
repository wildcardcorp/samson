from samson.utilities.bytes import Bytes
from samson.core.base_object import BaseObject
from types import FunctionType

class MatyasMeyerOseasConstruction(BaseObject):
    """
    Considered to be the dual of the Davies-Meyer construction. The Matyas-Meyer-Oseas construction is a
    one-way compression function built from a block cipher.
    """

    def __init__(self, initial_state: bytes, encryptor: FunctionType):
        """
        Parameters:
            initial_state (bytes): Bytes-like initial state that is the correct size for the underlying cipher.
            encryptor      (func): Function that takes in a plaintext and returns a ciphertext.
        """
        self.initial_state = initial_state
        self.encryptor = encryptor



    def yield_state(self, message: bytes) -> Bytes:
        """
        Yields the intermediate, hashed states of the `message`.

        Parameters:
            message (bytes): Message to be hashed.
        
        Returns:
            Bytes: Intermediate, hashed states.
        """
        block_size = len(self.initial_state)
        message = Bytes.wrap(message)

        message_blocks = message.chunk(block_size)
        last_state = self.initial_state

        for block in message_blocks:
            last_state = block ^ self.encryptor(last_state, block)
            yield last_state



    def hash(self, message: bytes) -> Bytes:
        """
        Yields the final, hashed state of the `message`.

        Parameters:
            message (bytes): Message to be hashed.
        
        Returns:
            Bytes: Fully-hashed state.
        """
        final_state = [_ for _ in self.yield_state(message)][-1]
        return final_state
