from types import FunctionType

class PaddingOracle(object):
    """
    Oracle that determines if a ciphertext has the correct padding or not. The `request` function must return a boolean indicating this.
    """

    def __init__(self, request_func: FunctionType):
        """
        Parameters:
            request_func (func): Function that takes in bytes and returns a boolean indicating whether the resulting plaintext has correct padding.
        """
        self.check_padding = request_func
