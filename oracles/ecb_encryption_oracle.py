class ECBEncryptionOracle(object):
    def __init__(self, request_func):
        self.request = request_func

    
    def find_block_size(self):
        baseline = len(self.request(b''))

        for i in range(33):
            curr_len = len(self.request(('A' * i).encode()))
            if  curr_len != baseline:
                return curr_len - baseline
