from tqdm import tqdm
from types import FunctionType
from samson.auxiliary.reporter import Reporter
from samson.auxiliary.progress import Progress

class TqdmReporter(Reporter):
    """
    Reporter that generates `tqdm` progress bars.
    """

    def __init__(self):
        self.current_contexts = {}


    def create_context(self, caller: object, func: FunctionType):
        """
        Creates a context for the `caller`.

        Parameters:
            caller (object): Caller object.
            func     (func): Function being reported on.
        """
        if not caller in self.current_contexts:
            self.current_contexts[caller] = []



    def cleanup_context(self, caller: object, func: FunctionType):
        """
        Cleans up a finished context. This class does nothing.

        Parameters:
            caller (object): Caller object.
            func     (func): Function being reported on.
        """
        [gen.close() for gen in self.current_contexts[caller]]
        del self.current_contexts[caller]



    def wrap_iteration(self, caller: object, iterable: object, kwargs) -> Progress:
        """
        Wraps the `iterable` in the appropriate Progres class.

        Parameters:
            caller (object): Caller object.
            func     (func): Function being reported on.
        
        Returns:
            Progress: Contextualized Progress object.
        """
        try:
            iterator = tqdm(iterable, **kwargs)
            self.current_contexts[caller].append(iterator)
            return iterator
        except KeyError:
            raise KeyError(f"Key '{caller}' not in contexts. Did you use the runtime decoration?")
