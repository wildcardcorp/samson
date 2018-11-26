from samson.utilities.manipulation import get_blocks
from samson.utilities.padding import md_pad
from samson.utilities.bytes import Bytes
from copy import deepcopy


class MerkleDamgardConstruction(object):
    def __init__(self, initial_state, compression_func, digest_size, block_size=64, endianness='big', bit_size=64):
        self.initial_state = deepcopy(initial_state)

        # Allows for direct use of class and subclass overriding simultaneously
        if compression_func:
            self.compression_func = compression_func

        self.digest_size = digest_size
        self.block_size = block_size
        self.endianness = endianness
        self.bit_size = bit_size



    def __repr__(self):
        return f"<MerkleDamgardConstruction initial_state={self.initial_state}, compression_func={self.compression_func}, block_size={self.block_size}, pad_func={self.pad_func}>"

    def __str__(self):
        return self.__repr__()


    def pad_func(self, message):
        return md_pad(message, None, self.endianness, bit_size=self.bit_size)


    def yield_state(self, message):
        state = self.initial_state

        for block in get_blocks(self.pad_func(message), self.block_size):
            state = self.compression_func(block, state)
            yield state


    def hash(self, message):
        final_state = list(self.yield_state(message))[-1]
        return final_state

    

    def length_extension(self, observed_output, message, bytes_to_append, secret_len):
        glue = md_pad(message, len(message) + secret_len, self.endianness, bit_size=self.bit_size)[len(message):]

        fake_len = secret_len + len(message) + len(glue) + len(bytes_to_append)

        new_hash_obj = deepcopy(self)
        new_hash_obj.initial_state = observed_output
        new_hash_obj.pad_func = lambda msg: md_pad(msg, fake_len, self.endianness, bit_size=self.bit_size)

        return Bytes(message + glue + bytes_to_append), new_hash_obj.hash(bytes_to_append)