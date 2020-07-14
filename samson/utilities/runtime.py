from samson.auxiliary.progress import Progress
from samson.ace.exploit import DynamicExploit, register_knowns
from functools import wraps
from types import FunctionType
import logging
import inspect
import sys
import os


URANDOM = open("/dev/urandom", "rb")


def default_poly_fft_heuristic(p1, p2):
    return p1.coeffs.sparsity * p2.coeffs.sparsity > (2**24 // p1.ring.structure_depth**2)


class RuntimeConfiguration(object):
    """
    Global runtime configuration. Allows for the dynamic configuration of existing samson code.
    """

    def __init__(self, log_fmt: str='%(asctime)s - %(name)s [%(levelname)s] %(message)s', use_color: bool=True):
        # Initialize reporter
        try:
            from samson.auxiliary.tqdm_handler import TqdmHandler
            from samson.auxiliary.tqdm_reporter import TqdmReporter
            from samson.auxiliary.colored_formatter import ColoredFormatter

            handler = TqdmHandler()

            self.use_color = use_color

            # Only color logs if attached to TTY
            if sys.stdout.isatty() and use_color:
                formatter = ColoredFormatter(fmt=log_fmt)
            else:
                formatter = logging.Formatter(fmt=log_fmt)

            handler.setFormatter(formatter)
            handler.setLevel(logging.DEBUG)

            self.reporter = TqdmReporter()
            self.set_global_log_handler(handler)

        except ImportError:
            from samson.auxiliary.reporter import Reporter
            self.reporter = Reporter()


        self.random = lambda size: URANDOM.read(size)
        self.poly_fft_heuristic = default_poly_fft_heuristic
        self.default_short_printer = lambda elem: elem.tinyhand()
        self.enable_poly_intercept = False


        # Initialize exploit mappings
        self.exploits = {}
        self.exploit_mappings = {}
        self.constraints = {}

        self.primitives = []

        self._contexts = {}



    def __repr__(self):
        return f"<RuntimeConfiguration: reporter={self.reporter}, enable_poly_intercept={self.enable_poly_intercept}>"

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
        @wraps(func)
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
        if cls not in self.exploit_mappings:
            self.exploit_mappings[cls] = []

        self.exploit_mappings[cls].append(attack)


    def register_primitive(self, cls):
        self.primitives.append(cls)


    def search_primitives(self, filter_func: FunctionType=lambda primitive: True):
        return [primitive for primitive in self.primitives if filter_func(primitive)]


    def show_primitives(self, filter_func: FunctionType=lambda primitive: True, sort_key: FunctionType=lambda primitive: str(primitive).split('.')[-1][:-2], reverse: bool=False):
        lines = []
        all_columns = [['Primitive', 'PrimitiveType', 'CipherType', 'SymmetryType', 'SecurityProofType', 'ConstructionType']]
        max_column_sizes = [len(col) for col in all_columns[0]]

        for primitive in sorted(self.search_primitives(filter_func), key=sort_key, reverse=reverse):
            columns = [str(primitive).split('.')[-1][:-2], primitive.PRIMITIVE_TYPE.name, primitive.CIPHER_TYPE.name, primitive.SYMMETRY_TYPE.name, primitive.SECURITY_PROOF.name, ', '.join([ctype.name for ctype in primitive.CONSTRUCTION_TYPES])]
            max_column_sizes = [max(len(col), curr_max) for col, curr_max in zip(columns, max_column_sizes)]
            all_columns.append(columns)

        for columns in all_columns:
            lines.append('| ' + ' | '.join([col.ljust(max_column_sizes[idx]) for idx, col in enumerate(columns)]) + ' |')
            lines.append('-' * len(lines[-1]))

        table = '=' * len(lines[-1]) + '\n' + '\n'.join(lines)
        print(table)


    def compare_bytes(self, a: bytes, b: bytes) -> bool:
        from hmac import compare_digest
        return compare_digest(a, b)


    def set_context(self, **ctx_kwargs) -> FunctionType:
        #func.__qualname__
        def wrapper_0(func):
            self._contexts[(func.__module__, func.__name__)] = RuntimeProxyContext(**ctx_kwargs)

            @wraps(func)
            def wrapper_1(*args, **kwargs):
                return func(*args, **kwargs)

            return wrapper_1

        return wrapper_0


    def get_context(self):
        stack  = inspect.stack()[1]
        func   = stack.function
        module = inspect.getmodule(stack[0])

        if module:
             module = module.__name__

        # caller_locals = frame[0].f_locals


        # if 'self' in caller_locals:
        #     caller_type = type(caller_locals['self'])
        # elif 'cls' in caller_locals:
        #     caller_type = caller_locals['cls']
        # else:
        #     raise ValueError("Calling func must have a 'self' or 'cls' identifier.")

        # f'{str(caller_type).split(".")[1][:-2]}.{func}'
        return self._contexts[(module, func)]



class RuntimeProxyContext(object):
    def __init__(self, **kwargs):
        self.attrs = kwargs

    def __getattr__(self, name):
        try:
            attr = self.attrs[name]
        except KeyError:
            attr = getattr(RUNTIME, name)

        return attr



RUNTIME = RuntimeConfiguration(use_color=(os.environ.get('USE_COLOR', 'True') == 'True'))
register_knowns()
