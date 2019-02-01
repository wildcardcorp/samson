import time

class TimeCounter(object):
    def __init__(self, time_step=30, initial_time=0):
        self.time_step = time_step
        self.initial_time = initial_time


    def __repr__(self):
        return f"<TimeCounter: time_step={self.time_step}, initial_time={self.initial_time}>"

    def __str__(self):
        return self.__repr__()


    def get_value(self):
        return (int(time.time()) - self.initial_time) // self.time_step
