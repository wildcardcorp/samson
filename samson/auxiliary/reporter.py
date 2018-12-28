from samson.auxiliary.progress import Progress
from types import FunctionType

class Reporter(object):
    """
    Reporter baseclass.
    """

    def create_context(self, caller: object, func: FunctionType):
        """
        Creates a context for the `caller`. This class does nothing.

        Parameters:
            caller (object): Caller object.
            func     (func): Function being reported on.
        """
        pass


    def cleanup_context(self, caller: object, func: FunctionType):
        """
        Cleans up a finished context. This class does nothing.

        Parameters:
            caller (object): Caller object.
            func     (func): Function being reported on.
        """
        pass


    def wrap_iteration(self, caller: object, iterable: object, kwargs) -> Progress:
        """
        Wraps the `iterable` in the appropriate Progres class.

        Parameters:
            caller (object): Caller object.
            func     (func): Function being reported on.
        
        Returns:
            Progress: Contextualized Progress object.
        """
        return Progress(iterable)
