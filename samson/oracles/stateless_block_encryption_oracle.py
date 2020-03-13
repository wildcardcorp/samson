from samson.oracles.chosen_plaintext_oracle import ChosenPlaintextOracle

class StatelessBlockEncryptionOracle(ChosenPlaintextOracle):
    """
    Oracle that provides an interface to a chosen-plaintext attack on a stateless block encryption.
    """

    def find_block_size(self) -> int:
        """
        Attempts to figure out the cipher's block size by probing the oracle.

        Returns:
            int: The cipher's block size.
        """
        baseline = len(self.encrypt(b''))

        for i in range(33):
            curr_len = len(self.encrypt(('A' * i).encode()))
            if  curr_len != baseline:
                return curr_len - baseline
