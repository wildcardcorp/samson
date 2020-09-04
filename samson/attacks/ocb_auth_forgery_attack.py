from samson.utilities.bytes import Bytes
from samson.oracles.chosen_plaintext_oracle import ChosenPlaintextOracle

class OCBAuthForgeryAttack(object):
    """
    Performs a authentication tag forgery attack.

    Conditions:
        * OCB2 is being used
        * The user has access to an oracle that accepts arbitrary plaintext and returns the ciphertext
    """

    def __init__(self, oracle: ChosenPlaintextOracle, block_size: int=16):
        """
        Parameters:
            oracle (ChosenPlaintextOracle): An oracle that takes in a bytes-like object and returns its eccryption.
            block_size               (int): The block size of the block cipher in bytes.
        """
        self.oracle = oracle
        self.block_size = block_size


    def execute(self, plaintext: bytes) -> (Bytes, Bytes):
        """
        Executes the attack.
        
        Parameters:
            plaintext (bytes): Plaintext to encrypt and build forgery of.

        Returns:
            (Bytes, Bytes): Formatted as (forged tag, new ciphertext).
        """
        encoded_length = Bytes(128).zfill(16)
        _tag, ciphertext = self.oracle.request(encoded_length + plaintext, b'')

        new_ciphertext = ciphertext[:16] ^ encoded_length
        new_tag = plaintext ^ ciphertext[16:]

        return new_tag, new_ciphertext
