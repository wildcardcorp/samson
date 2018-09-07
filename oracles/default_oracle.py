class DefaultOracle(object):
    def __init__(self, request_func):
        self.request = request_func