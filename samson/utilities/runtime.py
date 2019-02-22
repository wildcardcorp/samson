from samson.auxiliary.progress import Progress
from samson.ace.exploit import DynamicExploit, register_knowns
from types import FunctionType
import logging
import inspect

class RuntimeConfiguration(object):
    """
    Global runtime configuration. Allows for the dynamic configuration of existing samson code.
    """

    def __init__(self):
        # Initialize reporter
        try:
            from samson.auxiliary.tqdm_handler import TqdmHandler
            from samson.auxiliary.tqdm_reporter import TqdmReporter

            handler   = TqdmHandler()
            formatter = logging.Formatter(fmt='%(asctime)s - %(name)s [%(levelname)s] %(message)s')
            handler.setFormatter(formatter)
            handler.setLevel(logging.DEBUG)

            self.reporter = TqdmReporter()
            self.set_global_log_handler(handler)

        except ImportError:
            from samson.auxiliary.reporter import Reporter
            self.reporter = Reporter()


        # Initialize GRND_INT
        try:
            from gmpy2 import mpz
            self.GRND_INT = mpz
        except ImportError:
            try:
                from gmpy_cffi import mpz
                self.GRND_INT = mpz
            except ImportError:
                self.GRND_INT = int


        # Initialize exploit mappings
        self.exploits = {}
        self.exploit_mappings = {}
        self.constraints = {}



    def __repr__(self):
        return f"<RuntimeConfiguration: GRND_INT={self.GRND_INT}, reporter={self.reporter}>"

    def __str__(self):
        return self.__repr__()



    def set_global_log_handler(self, handler: logging.StreamHandler, log_level: int=logging.DEBUG):
        """
        Replaces the default global log handler.

        Parameters:
            handler (StreamHandler): New log StreamHandler.
            log_level         (int): Log level for global logging.
        """
        root_logger = logging.getLogger()
        root_logger.handlers = []
        root_logger.addHandler(handler)
        root_logger.propagate = False
        root_logger.setLevel(log_level)



    def report_progress(self, iterable: object, **kwargs) -> Progress:
        """
        Reports context-specific progress to the runtime reporter.

        Parameters:
            iterable (iterable): Iterable to report for. Can be set to `None`/updated manually.
            **kwargs   (kwargs): Keyword arguments to pass to the returned Progress object.
        
        Returns:
            Progress: Progress reporting object.
        """
        caller_locals = inspect.stack()[1][0].f_locals

        if 'self' in caller_locals:
            key = 'self'
        elif 'cls' in caller_locals:
            key = 'cls'
        else:
            raise ValueError("Calling func must have a 'self' or 'cls' identifier.")

        return self.reporter.wrap_iteration(caller_locals[key], iterable, kwargs)



    def report(self, func: FunctionType) -> FunctionType:
        """
        Initializes a reporting context for an object or class method.

        Parameters:
            func (func): Object or class method.

        Returns:
            func: Contextualized function.
        """
        def new_func(*args, **kwargs):
            result = None
            caller = args[0]

            try:
                self.reporter.create_context(caller, func)
                result = func(*args, **kwargs)
            finally:
                self.reporter.cleanup_context(caller, func)

            return result

        return new_func



    def register_exploit(self, cls, consequence, requirements):
        self.exploits[cls] = DynamicExploit(cls, consequence, requirements)


    def register_exploit_mapping(self, cls, attack):
        self.exploit_mappings[cls] = attack


RUNTIME = RuntimeConfiguration()
register_knowns()
