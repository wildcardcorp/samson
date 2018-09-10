from samson.utilities import get_blocks, md_pad

class MerkleDamgardConstruction(object):
    def __init__(self, initial_state, compression_func, pad_func=lambda msg: md_pad(msg), block_size=64):
        self.pad_func = pad_func
        self.initial_state = initial_state
        self.compression_func = compression_func
        self.block_size = block_size


    def yield_state(self, message):
        state = self.initial_state

        for block in get_blocks(self.pad_func(message), self.block_size):
            state = self.compression_func(block, state)
            yield state


    def hash(self, message):
        final_state = [_ for _ in self.yield_state(message)][-1]
        return final_state