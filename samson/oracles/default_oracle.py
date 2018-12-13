from types import FunctionType

class DefaultOracle(object):
    """
    Simple oracle that provides a `request` function.
    """

    def __init__(self, request_func: FunctionType):
        """
        Parameters:
            request_func (func): Function that provides the oracle.
        """
        self.request = request_func
