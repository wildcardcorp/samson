from samson.oracles.default_oracle import DefaultOracle
from samson.utilities.bytes import Bytes
import struct
import string

import logging
log = logging.getLogger(__name__)


alphabet = (string.ascii_lowercase + string.ascii_uppercase + string.digits + '=/+' + ':;').encode()
padding_chars = ')(\{\}\\[]<%@#^`~$*!|`'[::-1].encode() + b'>.\'_,?;:+-='

class CRIMEAttack(object):
    """
    Performs a compression ratio side channel attack.

    Even if a message is encrypted, information about the contents of the message can still be leaked. CRIME/BREACH measures
    is an adaptive chosen-plaintext attack that measures the size of a compressed-then-encrypted message. By crafting our insertions,
    we can determine whether specific patterns exist in the message and eventually recover entire plaintexts.

    Conditions:
        * The user has access to a length oracle that takes in arbitrary bytes and outputs the compressed length.
    """

    def __init__(self, oracle: DefaultOracle, alphabet: bytes=alphabet, padding_chars: bytes=padding_chars):
        """
        Parameters:
            oracle (DefaultOracle): A length oracle that takes in arbitrary bytes and outputs the compressed length.
            alphabet       (bytes): Allowed characters to try.
            padding_chars  (bytes): Characters not likely to show up and can be used as "padding."
        """
        self.oracle = oracle
        self.alphabet = alphabet
        self.padding_chars = padding_chars



    def execute(self, known_plaintext: bytes, secret_len: int, constant_padding: bytes=b'\t\t\t\t\t') -> Bytes:
        """
        Executes the attack.

        Parameters:
            known_plaintext  (bytes): Partial known plaintext to seed the attack.
            secret_len         (int): Length of the secret. Better to be higher than lower.
            constant_padding (bytes): A padding that is always appended. This parameter can easily be the difference between a failure and success.
        
        Returns:
            Bytes: The recovered plaintext.
        """
        plaintext = known_plaintext

        padding = self.find_padding(plaintext, constant_padding)

        if padding == None:
            raise Exception("No suitable padding found")

        ctr = 0
        while (len(plaintext) - len(known_plaintext)) < secret_len:
            log.debug('Attempt format of "{}"'.format((plaintext + b'{}' + padding).decode()))
            padded_sizes = [(struct.pack('B', char), self.oracle.request(plaintext + struct.pack('B', char) + padding + constant_padding)) for char in self.alphabet]

            sorted_sizes = sorted(padded_sizes, key=lambda req: req[1])
            log.debug(f'Sizes for iteration {ctr}: {sorted_sizes}')

            if sorted_sizes[0][1] == sorted_sizes[1][1]:
                return Bytes(plaintext)
            else:
                plaintext += sorted_sizes[0][0]

            ctr += 1

        return Bytes(plaintext)



    def find_padding(self, payload: bytes, constant_padding: bytes) -> bytes:
        """
        Internal function. Used to find an appropriate padding for the oracle.
        """
        reference_len = self.oracle.request(payload)
        padding = b''

        log.debug('Attempting to find padding')

        for char in self.padding_chars:
            padding += struct.pack('B', char)
            new_len = self.oracle.request(payload + padding + constant_padding)

            if new_len > reference_len:
                padding = padding[:-1]
                log.debug('Found suitable padding "{}"'.format(padding.decode()))
                return padding
