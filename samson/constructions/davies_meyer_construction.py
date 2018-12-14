from samson.utilities.bytes import Bytes
from types import FunctionType

# https://en.wikipedia.org/wiki/One-way_compression_function#Davies%E2%80%93Meyer
class DaviesMeyerConstruction(object):
    """
    A Davies-Meyer construction is a one-way compression function built from a block cipher.
    """

    def __init__(self, initial_state: bytes, encryptor: FunctionType):
        """
        Parameters:
            initial_state (bytes): Bytes-like initial state that is the correct size for the underlying cipher.
            encryptor      (func): Function that takes in a plaintext and returns a ciphertext.
        """
        self.initial_state = Bytes.wrap(initial_state)
        self.block_size = len(self.initial_state)
        self.encryptor = encryptor


    def __repr__(self):
        return f"<DaviesMeyerConstruction initial_state={self.initial_state}, encryptor={self.encryptor}, block_size={self.block_size}>"

    def __str__(self):
        return self.__repr__()


    def yield_state(self, message: bytes):
        """
        Yields the intermediate, hashed states of the `message`.

        Parameters:
            message (bytes): Message to be hashed.
        
        Returns:
            generator: Intermediate, hashed states.
        """
        message = Bytes.wrap(message)
        last_state = self.initial_state

        for block in message.chunk(self.block_size):
            last_state = self.encryptor(block, last_state) ^ last_state
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



    @staticmethod
    def generate_fixed_point(block_cipher: object, message: bytes, block_size: int):
        """
        Generates a Davies-Meyer fixed point. A fixed point is a state in which its output matches
        its input, and, therefore, infinitely produces itself.

        Parameters:
            block_cipher  (type): Block cipher type.
            message       (bytes): Message you want to be fixed point.
            block_size      (int): Block size of `block_cipher`.

        Returns:
            DaviesMeyerConstruction: A DaviesMeyerConstruction with the initial state set to the fixed point.
        """
        message = Bytes.wrap(message)
        first_block = message.chunk(block_size)[0]

        initial_state = block_cipher(first_block).decrypt(Bytes(b'').zfill(block_size))

        return DaviesMeyerConstruction(initial_state=initial_state, encryptor=lambda key, msg: block_cipher(key).encrypt(msg))
