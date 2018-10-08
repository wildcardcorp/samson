class EncryptionOracle(object):
    def __init__(self, request_func):
        self.encrypt = request_func