from samson.core.attack_model import AttackModel
from samson.oracles.known_plaintext_oracle import KnownPlaintextOracle
from samson.oracles.oracle import Oracle
from samson.utilities.exceptions import *
from samson.core.metadata import IORelationType
from samson.utilities.bytes import Bytes
from types import FunctionType

import logging
log = logging.getLogger(__name__)

class ChosenCiphertextOracle(Oracle):
    """
    Simple oracle that provides a `request` function.
    """

    ATTACK_MODEL = AttackModel.CHOSEN_CIPHERTEXT

    def __init__(self, request_func: FunctionType):
        """
        Parameters:
            request_func (func): Function that provides the oracle.
        """
        self.request = request_func


    def downconvert(self, attack_model: AttackModel, generator: FunctionType=lambda: Bytes.random(8)):
        if attack_model == self.ATTACK_MODEL:
            return self

        else:
            def oracle_func():
                pt = generator()
                ct = self.request(pt)

                return pt, ct

            return KnownPlaintextOracle(oracle_func).downconvert(attack_model, generator)



    def test_io_relation(self) -> int:
        def get_log_size(reverse=False):
            iterator = range(12)

            if reverse:
                iterator = reversed(iterator)

            for size in iterator:
                try:
                    self.request(b'a' * 2**size)

                except CiphertextLengthException:
                    continue

                except DecryptionException:
                    pass

                break

            return size



        for i in range(512):
            try:
                self.request(b'a'*i)

            except CiphertextLengthException:
                continue

            except DecryptionException:
                pass

            break


        min_size = i
        max_size = self.test_max_input()
        #binary_search(search_func, 2**16384)

        #get_log_size()
        #max_size = get_log_size(True)

        # Public key crypto is FIXED but will take in anything between zero and `n`
        # It will almost always be 2**0 (1), so we take the max as the block size instead.
        # This still works for stream ciphers because they won't have a max and will iterate back to zero.
        block_size = min_size if min_size else max_size

        for size_mod in range(block_size, -1, -1):
            try:
                self.request(b'a' * (block_size + size_mod))
                break

            except CiphertextLengthException:
                continue

            except DecryptionException:
                break


        # Determine IO relation
        if size_mod:
            io_relation = IORelationType.EQUAL
        else:
            io_relation = IORelationType.FIXED

        return {"io_relation": io_relation, "block_size": block_size}
