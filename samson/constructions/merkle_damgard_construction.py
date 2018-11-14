from samson.utilities.manipulation import get_blocks
from samson.utilities.padding import md_pad

class MerkleDamgardConstruction(object):
    def __init__(self, initial_state, compression_func, pad_func=md_pad, block_size=64):
        self.pad_func = pad_func
        self.initial_state = initial_state
        self.compression_func = compression_func
        self.block_size = block_size



    def __repr__(self):
        return f"<MerkleDamgardConstruction initial_state={self.initial_state}, compression_func={self.compression_func}, block_size={self.block_size}, pad_func={self.pad_func}>"

    def __str__(self):
        return self.__repr__()



    def yield_state(self, message):
        state = self.initial_state

        for block in get_blocks(self.pad_func(message), self.block_size):
            state = self.compression_func(block, state)
            yield state


    def hash(self, message):
        final_state = list(self.yield_state(message))[-1]
        return final_state