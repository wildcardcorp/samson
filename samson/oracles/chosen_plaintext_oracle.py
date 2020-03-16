from samson.core.metadata import IORelationType
from samson.utilities.exceptions import OracleException
from samson.utilities.bytes import Bytes
from samson.math.general import kth_root
from types import FunctionType
import math

import logging
log = logging.getLogger(__name__)


class ChosenPlaintextOracle(object):
    """
    Oracle that provides an interface to a chosen-plaintext attack.
    """

    def __init__(self, request_func: FunctionType):
        """
        Parameters:
            request_func (func): Function that takes in bytes and returns a ciphertext.
        """
        self.encrypt = request_func


    def test_io_relation(self, min_input_len: int=1) -> dict:
        sample   = self.encrypt(b'a'*min_input_len)
        base_len = len(sample)
        new_len  = base_len

        i       = min_input_len + 1
        io_diff = []

        log.debug(f'Starting block size/output size testing')
        while base_len == new_len and i < 64:
            sample  = self.encrypt(b'a'*i)
            new_len = len(sample)
            io_diff.append(new_len - base_len)
            i += 1

        # Determine IO relation
        if any(io_diff):
            io_relation = IORelationType.EQUAL
        else:
            io_relation = IORelationType.FIXED


        return {"io_relation": io_relation, "block_size": (new_len - base_len) or base_len}


    def test_max_input(self, max_int: int=2**16384) -> int:
        # See if there's a max size
        start_idx = 0
        end_idx   = max_int

        # Use 'max_int' as a canary. If the primitive will take 'max_int', then
        # it's most likely going to take anything. Only run this test if we know the primitive
        # has a fixed output size (e.g. hashes and number-theoretical crypto).
        should_test_max = False
        while True:
            try:
                self.encrypt(Bytes(max_int))
                log.info(f'Oracle seems to take in arbitrary-sized inputs')
                break

            except OracleException:
                should_test_max = True
                end_idx = max_int
                break

            except ValueError:
                max_int = kth_root(max_int, 2)
                log.warning(f'Oracle returned ValueError. Reducing MAX_TEST_INPUT to 2^{int(math.log(max_int, 2))}')


        # Use binary search to find max input size. This is both the most efficient method of finding
        # the max size and the most precise. For example, if the primitive is RSA and rejects inputs
        # larger than its modulus, then "end_idx" will be the modulus.
        max_val = -1

        if should_test_max:
            log.debug(f'Starting max input testing')

            while end_idx - 1 != start_idx:
                current = (end_idx + start_idx) // 2

                try:
                    self.encrypt(Bytes(current))
                    start_idx = current

                except OracleException:
                    end_idx = current

            log.info(f'Max input size: {round(math.log(end_idx, 2), 1)} bits')
            max_val = end_idx

        else:
            log.debug(f'Skipping max input testing')

        return max_val



    def test_stateless_blocks(self, block_size: int, num_blocks: int=4) -> bool:
        blocks = Bytes.wrap(self.encrypt(b'a'*block_size*num_blocks)).chunk(block_size)
        return len(set([bytes(block) for block in blocks])) < num_blocks
