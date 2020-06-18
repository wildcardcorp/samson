from types import FunctionType
from samson.core.attack_model import AttackModel

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
