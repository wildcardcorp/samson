from types import FunctionType
from samson.core.attack_model import AttackModel
from samson.oracles.known_plaintext_oracle import KnownPlaintextOracle
from samson.utilities.bytes import Bytes

class ChosenCiphertextOracle(object):
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
