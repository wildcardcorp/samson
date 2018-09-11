from samson.utilities.manipulation import get_blocks, xor_buffs

class DaviesMeyerConstruction(object):
    def __init__(self, initial_state, encryptor, decryptor):
        self.initial_state = initial_state
        self.encryptor = encryptor
        self.decryptor = decryptor


    def yield_state(self, message):
        block_size = len(self.initial_state)

        message_blocks = get_blocks(message, block_size=block_size)
        last_state = self.initial_state

        for block in message_blocks:
            last_state = xor_buffs(self.encryptor(block, last_state), last_state)
            yield last_state



    def hash(self, message):
        final_state = [_ for _ in self.yield_state(message)][-1]
        return final_state



    def generate_fixed_point(self, message):
        block_size = len(self.initial_state)
        message_blocks = get_blocks(message, block_size=block_size)

        payload = self.decryptor(message_blocks[0], b'\x00' * 16)