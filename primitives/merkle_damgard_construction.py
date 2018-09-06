from samson.primitives.sha1 import generate_padding
from samson.utilities import get_blocks

class MerkleDamgardConstruction(object):
    def __init__(self, initial_state, compression_func, pad_func=lambda msg: msg + generate_padding(len(msg)), output_size=128):
        self.pad_func = pad_func
        self.initial_state = initial_state
        self.compression_func = compression_func
        self.output_size = output_size


    def yield_state(self, message):
        state = self.initial_state
        num_bytes = self.output_size

        for block in get_blocks(self.pad_func(message), num_bytes):
            state = self.compression_func(block, state)[:num_bytes]
            yield state


    def hash(self, message):
        final_state = [_ for _ in self.yield_state(message)][-1]
        return final_state