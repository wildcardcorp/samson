from samson.core.metadata import IORelationType
from samson.utilities.bytes import Bytes
from samson.oracles.oracle import Oracle
from types import FunctionType

import logging
log = logging.getLogger(__name__)


class ChosenPlaintextOracle(Oracle):
    """
    Oracle that provides an interface to a chosen-plaintext attack.
    """

    def __init__(self, request_func: FunctionType):
        """
        Parameters:
            request_func (func): Function that takes in bytes and returns a ciphertext.
        """
        self.request = request_func


    def test_io_relation(self, min_input_len: int=1) -> dict:
        sample   = self.request(b'a'*min_input_len)
        base_len = len(sample)
        new_len  = base_len

        i       = min_input_len + 1
        io_diff = []

        log.debug(f'Starting block size/output size testing')
        while base_len == new_len and i < 64:
            sample  = self.request(b'a'*i)
            new_len = len(sample)
            io_diff.append(new_len - base_len)
            i += 1

        # Determine IO relation
        if any(io_diff):
            io_relation = IORelationType.EQUAL
        else:
            io_relation = IORelationType.FIXED


        return {"io_relation": io_relation, "block_size": (new_len - base_len) or base_len}



    def test_stateless_blocks(self, block_size: int, num_blocks: int=4) -> bool:
        blocks = Bytes.wrap(self.request(b'a'*block_size*num_blocks)).chunk(block_size)
        return len(set([bytes(block) for block in blocks])) < num_blocks
