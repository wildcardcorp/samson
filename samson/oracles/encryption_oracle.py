from types import FunctionType

class EncryptionOracle(object):
    """
    Oracle that provides an interface to a chosen-plaintext attack.
    """

    def __init__(self, request_func: FunctionType):
        """
        Parameters:
            request_func (func): Function that takes in bytes and returns a ciphertext.
        """
        self.encrypt = request_func
