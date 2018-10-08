# Oracle that determines if a ciphertext has the correct padding or not. The `request` function must return a boolean indicating this.
class PaddingOracle(object):
    def __init__(self, request_func):
        self.check_padding = request_func