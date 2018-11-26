from samson.utilities.bytes import Bytes

# https://en.wikipedia.org/wiki/One-way_compression_function#Davies%E2%80%93Meyer
class DaviesMeyerConstruction(object):
    def __init__(self, initial_state, encryptor):
        self.initial_state = Bytes.wrap(initial_state)
        self.block_size = len(self.initial_state)
        self.encryptor = encryptor
    


    def __repr__(self):
        return f"<DaviesMeyerConstruction initial_state={self.initial_state}, encryptor={self.encryptor}, block_size={self.block_size}>"

    def __str__(self):
        return self.__repr__()


    def yield_state(self, message):
        message = Bytes.wrap(message)
        last_state = self.initial_state

        for block in message.chunk(self.block_size):
            last_state = self.encryptor(block, last_state) ^ last_state
            yield last_state



    def hash(self, message):
        final_state = [_ for _ in self.yield_state(message)][-1]
        return final_state



    @staticmethod
    def generate_fixed_point(block_cipher, message, block_size):
        message = Bytes.wrap(message)
        first_block = message.chunk(block_size)[0]

        initial_state = block_cipher(first_block).decrypt(Bytes(b'').zfill(block_size))

        return DaviesMeyerConstruction(initial_state=initial_state, encryptor=lambda key, msg: block_cipher(key).encrypt(msg))