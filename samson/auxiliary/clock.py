from samson.oracles.timing_oracle import TimingOracle
import time

class Clock(object):
    def __init__(self):
        self.lag = 0
    

    # TODO: Come up with a sane way to compute lag. How do we know how long it takes to query
    # the oracle rather than get a response back?
    def synchronize(self, oracle_func, **oracle_args):
        timing_oracle = TimingOracle(lambda x: oracle_func())
        timing, _jitter = timing_oracle.get_timing(None, **oracle_args)

        current_time = time.time()
        oracle_time = oracle_func()

        self.lag = oracle_time - current_time
        

    def get_clock(self):
        return time.time() - self.lag
