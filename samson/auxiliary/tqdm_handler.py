import logging
from tqdm import tqdm, trange

class TqdmHandler(logging.StreamHandler):
    def emit(self, record):
        msg = self.format(record)
        tqdm.write(msg)