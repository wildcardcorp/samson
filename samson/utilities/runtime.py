import logging

class RuntimeConfiguration(object):
    def __init__(self):
        try:
            from tqdm import tqdm
            from samson.auxiliary.tqdm_handler import TqdmHandler
            handler = TqdmHandler()
            self.set_global_log_handler(handler)
            self.ITER_WRAPPER = tqdm

        except ImportError:
            self.ITER_WRAPPER = lambda x:x
            pass

        try:
            from gmpy2 import mpz
            self.GRND_INT = mpz
        except ImportError:
            try:
                from gmpy_cffi import mpz
                self.GRND_INT = mpz
            except ImportError:
                self.GRND_INT = int



    def __repr__(self):
        return f"<RuntimeConfiguration: GRND_INT={self.GRND_INT}, ITER_WRAPPER={self.ITER_WRAPPER}>"

    def __str__(self):
        return self.__repr__()


    def set_global_log_handler(self, handler):
        formatter = logging.Formatter(fmt='%(asctime)s - %(name)s [%(levelname)s] %(message)s')
        handler.setFormatter(formatter)

        root_logger = logging.getLogger()
        root_logger.handlers = []
        root_logger.addHandler(handler)
        root_logger.propagate = False


GLOBAL_CFG = RuntimeConfiguration()