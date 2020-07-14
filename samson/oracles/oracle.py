from samson.utilities.exceptions import CiphertextLengthException, DecryptionException
from samson.utilities.bytes import Bytes
from samson.utilities.general import binary_search
from samson.math.general import kth_root
from types import FunctionType
import math

import logging
log = logging.getLogger(__name__)

class Oracle(object):
    """
    Simple oracle that provides a `request` function.
    """

    def __init__(self, request_func: FunctionType):
        """
        Parameters:
            request_func (func): Function that provides the oracle.
        """
        self.request = request_func



    def test_max_input(self, max_int: int=2**16383) -> int:
        # Use 'max_int' as a canary. If the primitive will take 'max_int', then
        # it's most likely going to take anything. Only run this test if we know the primitive
        # has a fixed output size (e.g. hashes and number-theoretical crypto).
        should_test_max = False
        while True:
            try:
                self.request(Bytes(max_int))

            except CiphertextLengthException:
                should_test_max = True
                break

            except DecryptionException:
                pass

            except ValueError:
                max_int = kth_root(max_int, 2)
                log.warning(f'Oracle returned ValueError. Reducing MAX_TEST_INPUT to 2^{int(math.log(max_int, 2))}')
                continue

            log.info('Oracle seems to take in arbitrary-sized inputs')
            break


        # Use binary search to find max input size. This is both the most efficient method of finding
        # the max size and the most precise. For example, if the primitive is RSA and rejects inputs
        # larger than its modulus, then "end_idx" will be the modulus.
        max_val = -1

        if should_test_max:
            log.debug('Starting max input testing')

            def search_func(n):
                try:
                    self.request(Bytes(n))

                except CiphertextLengthException:
                    return False

                except DecryptionException:
                    pass

                return True

            max_val = binary_search(search_func, max_int)

            log.info(f'Max input size: {round(math.log(max_val, 2), 1)} bits')

        else:
            log.debug('Skipping max input testing')

        return max_val
