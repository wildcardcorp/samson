from types import FunctionType
from samson.core.attack_model import AttackModel
from samson.utilities.runtime import RUNTIME
from samson.utilities.bytes import Bytes

class CiphertextOnlyOracle(object):
    """
    Simple oracle that provides a `request` function.
    """

    ATTACK_MODEL = AttackModel.CIPHERTEXT_ONLY

    def __init__(self, request_func: FunctionType):
        """
        Parameters:
            request_func (func): Function that provides the oracle.
        """
        self.request = request_func



    def downconvert(self, attack_model: AttackModel):
        if attack_model == self.ATTACK_MODEL:
            return self

        else:
            raise ValueError(f"{self.ATTACK_MODEL} cannot be downconverted to {attack_model}")


    def test_bytewise_malleability(self, ciphertext, test_range: range=None, threads: int=5):
        ct_len = len(ciphertext)
        ciphertext = Bytes.wrap(ciphertext)

        if not test_range:
            test_range = range(ct_len)

        @RUNTIME.threaded(threads=threads)
        def test_byte(i):
            return [self.request(ciphertext ^ Bytes(b).zfill(ct_len-i).pad_congruent_right(ct_len)) for b in range(256)]

        return test_byte(test_range)
