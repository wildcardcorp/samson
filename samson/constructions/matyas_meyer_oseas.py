from samson.utilities.bytes import Bytes

class MatyasMeyerOseasConstruction(object):
    def __init__(self, initial_state, encryptor, decryptor):
        self.initial_state = initial_state
        self.encryptor = encryptor
        self.decryptor = decryptor


    def yield_state(self, message):
        block_size = len(self.initial_state)
        message = Bytes.wrap(message)

        message_blocks = message.chunk(block_size)
        last_state = self.initial_state

        for block in message_blocks:
            last_state ^= self.encryptor(last_state, block)
            yield last_state



    def hash(self, message):
        final_state = [_ for _ in self.yield_state(message)][-1]
        return final_state