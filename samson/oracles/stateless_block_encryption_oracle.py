from samson.oracles.encryption_oracle import EncryptionOracle

class StatelessBlockEncryptionOracle(EncryptionOracle):
    def find_block_size(self):
        baseline = len(self.encrypt(b''))

        for i in range(33):
            curr_len = len(self.encrypt(('A' * i).encode()))
            if  curr_len != baseline:
                return curr_len - baseline