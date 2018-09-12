from samson.utilities.manipulation import get_blocks, xor_buffs
from samson.utilities.padding import pkcs7_pad, pkcs7_unpad
import struct

import logging
log = logging.getLogger(__name__)

# https://grymoire.wordpress.com/2014/12/05/cbc-padding-oracle-attacks-simplified-key-concepts-and-pitfalls/
class CBCPaddingOracleAttack(object):
    # Expects a PaddingOracle
    def __init__(self, oracle, iv, block_size=16):
        self.oracle = oracle
        self.iv = iv
        self.block_size = block_size


    def execute(self, ciphertext):
        blocks = get_blocks(ciphertext, self.block_size)
        reversed_blocks = blocks[::-1]

        plaintexts = []

        for i, block in enumerate(reversed_blocks):
            log.debug("Starting iteration {}".format(i))
            plaintext = b''

            if i == len(reversed_blocks) - 1:
                preceding_block = self.iv
            else:
                preceding_block = reversed_blocks[i + 1]

            for _ in range(len(block)):
                last_working_char = b'\x00'

                for possible_char in range(256):
                    test_byte = struct.pack('B', possible_char)
                    payload = test_byte + plaintext
                    prefix = b'\x00' * (self.block_size - len(payload))

                    padding = xor_buffs(struct.pack('B', len(payload)) * (len(payload)), payload)

                    fake_block = prefix + padding
                    exploit_block = xor_buffs(fake_block, preceding_block)
                    new_cipher = exploit_block + block

                    if self.oracle.check_padding(bytes(new_cipher)):
                        log.debug("Found working byte: {}".format(test_byte))
                        last_working_char = test_byte

                plaintext = last_working_char + plaintext

            plaintexts.append(plaintext)
        return pkcs7_unpad(b''.join(plaintexts[::-1]), self.block_size)