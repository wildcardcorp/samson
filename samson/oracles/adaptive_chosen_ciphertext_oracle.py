from types import FunctionType
from samson.core.attack_model import AttackModel
from samson.oracles.chosen_ciphertext_oracle import ChosenCiphertextOracle
from samson.utilities.bytes import Bytes

class AdaptiveChosenCiphertextOracle(object):
    """
    Simple oracle that provides a `request` function.
    """

    ATTACK_MODEL = AttackModel.ADAPTIVE_CHOSEN_CIPHERTEXT

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
            return ChosenCiphertextOracle(self.request).downconvert(attack_model, generator)

        else:
            raise ValueError(f"{self.ATTACK_MODEL} cannot be downconverted to {attack_model}")
