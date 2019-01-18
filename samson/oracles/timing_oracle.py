from types import FunctionType

class TimingOracle(object):
    """
    Oracle that times the `request_func`.
    """

    def __init__(self, request_func: FunctionType):
        """
        Parameters:
            request_func (func): Function that takes in bytes.
        """
        self.request_func = request_func


    def get_timing(self):
        pass
