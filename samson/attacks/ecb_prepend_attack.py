from samson.utilities.manipulation import get_blocks
from samson.utilities.padding import pkcs7_unpad
import struct

import logging
log = logging.getLogger(__name__)

class ECBPrependAttack(object):
    # Expects a StatelessBlockEncryptionOracle
    def __init__(self, oracle):
        self.oracle = oracle


    def execute(self):
        baseline = len(self.oracle.encrypt(b''))
        block_size = self.oracle.find_block_size()

        plaintexts = []
        for curr_block in range(baseline // block_size):
            log.debug("Starting iteration {}".format(curr_block))
            
            plaintext = b''
            for curr_byte in range(block_size):
                if curr_block == 0:
                    payload = ('A' * (block_size - (curr_byte + 1))).encode()
                else:
                    payload = plaintexts[-1][curr_byte + 1:]

                one_byte_short = get_blocks(self.oracle.encrypt(payload), block_size=block_size)[curr_block]

                for i in range(256):
                    curr_byte = struct.pack('B', i)
                    ciphertext = self.oracle.encrypt(payload + plaintext + curr_byte)

                    # We're always editing the first block to look like block 'curr_block'
                    if get_blocks(ciphertext, block_size=block_size)[0] == one_byte_short:
                        plaintext += curr_byte
                        break

            plaintexts.append(plaintext)
        return pkcs7_unpad(b''.join(plaintexts), block_size=block_size)
