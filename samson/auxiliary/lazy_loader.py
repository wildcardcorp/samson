
import importlib
import types

class LazyLoader(types.ModuleType):
    """
    References:
        https://github.com/tensorflow/tensorflow/blob/master/tensorflow/python/util/lazy_loader.py
        https://wil.yegelwel.com/lazily-importing-python-modules/
    """
    def __init__(self, local_name: str, parent_module_globals: dict, name: str):
        self._local_name = local_name
        self._parent_module_globals = parent_module_globals

        super(LazyLoader, self).__init__(name)


    def _load(self):
        # Import the target module and insert it into the parent's namespace
        module = importlib.import_module(self.__name__)
        self._parent_module_globals[self._local_name] = module

        # Update this object's dict so that if someone keeps a reference to the
        #   LazyLoader, lookups are efficient (__getattr__ is only called on lookups
        #   that fail).
        self.__dict__.update(module.__dict__)

        return module


    def __getattr__(self, item):
        module = self._load()
        return getattr(module, item)


    def __dir__(self):
        module = self._load()
        return dir(module)
