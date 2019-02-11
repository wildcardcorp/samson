from types import FunctionType
from timeit import Timer, default_timer
from math import ceil

def average(items):
    return sum(items) / len(items)


def percentile_filter(percentile, items):
    items = sorted(items)
    return items[:ceil(len(items) * percentile)]


class TimingOracle(object):
    """
    Oracle that times the `request_func`.
    """

    def __init__(self, request_func: FunctionType, timer: object=default_timer, filters: list=[], aggregator: FunctionType=average):
        """
        Parameters:
            request_func (func): Function that takes in bytes.
            timer      (object): Timer object that is used by Python's internal Timer class.
            filters      (list): List of filter functions that take in a list of items and output the items that satisfy the filter.
            aggregator   (func): Aggregation function (e.g. average).
        """
        self.request_func = request_func
        self.filters = filters
        self.timer = timer
        self.aggregator = aggregator



    def get_timing(self, message: object, sample_size: int=1000) -> (float, float):
        """
        Times running the `request_func` with `message`.

        Parameters:
            message  (object): Message to send to oracle function.
            sample_size (int): Number of samples to collect.
        
        Returns:
            (float, float): Timing information formatted as (timing, jitter).
        """
        timer = Timer(stmt=lambda: self.request_func(message), timer=self.timer)
        timings = []

        for _ in range(sample_size):
            timings.append(timer.timeit(number=1))

        for filt in self.filters:
            timings = filt(timings)

        return self.aggregator(timings), average([abs(a-b) for a,b in zip(timings, timings[1:])])
