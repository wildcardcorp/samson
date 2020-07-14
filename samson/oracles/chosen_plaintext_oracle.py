from samson.core.metadata import IORelationType
from samson.utilities.bytes import Bytes
from samson.oracles.oracle import Oracle
from samson.analysis.general import count_items
from samson.math.general import gcd
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

        log.debug('Starting block size/output size testing')
        while base_len == new_len and i < 64 or i < 32:
            sample  = self.request(b'a'*i)
            new_len = len(sample)
            io_diff.append(new_len)
            i += 1


        size_counts = sorted(count_items(io_diff).values())

        # Determine IO relation

        # This heuristic takes into account random size fluctuations
        # in number theoretical algorithms like RSA. There's a
        # 1 in 5,961,809 chance of getting five or more size differences
        # in a FIXED algorithm.

        # `probability_of_at_least_x_occurences(32, 5, 1/256)`
        if sum(size_counts[:-1]) > 4:
            io_relation = IORelationType.EQUAL
        else:
            io_relation = IORelationType.FIXED


        return {"io_relation": io_relation, "block_size": gcd(new_len, base_len)}



    def test_stateless_blocks(self, block_size: int, num_blocks: int=4) -> bool:
        blocks = Bytes.wrap(self.request(b'a'*block_size*num_blocks)).chunk(block_size)
        return len(set([bytes(block) for block in blocks])) < num_blocks
