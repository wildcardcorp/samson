from types import FunctionType
from samson.core.attack_model import AttackModel
from samson.oracles.ciphertext_only_oracle import CiphertextOnlyOracle
from samson.utilities.bytes import Bytes

class KnownPlaintextOracle(object):
    """
    Simple oracle that provides a `request` function.
    """

    ATTACK_MODEL = AttackModel.KNOWN_PLAINTEXT

    def __init__(self, request_func: FunctionType):
        """
        Parameters:
            request_func (func): Function that provides the oracle.
        """
        self.request = request_func


    def downconvert(self, attack_model: AttackModel, generator: FunctionType=lambda: Bytes.random(8)):
        if attack_model == self.ATTACK_MODEL:
            return self

        elif self.ATTACK_MODEL.implies(attack_model):
            return CiphertextOnlyOracle(lambda: self.request()[1])

        else:
            raise ValueError(f"{self.ATTACK_MODEL} cannot be downconverted to {attack_model}")
