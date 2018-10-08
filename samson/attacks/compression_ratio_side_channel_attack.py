import string
import struct

import logging
log = logging.getLogger(__name__)

alphabet = (string.ascii_lowercase + string.ascii_uppercase + string.digits + '=/+' + ':;').encode()
padding_chars = ')(\{\}\\[]<%@#^`~$*!|`'[::-1].encode() + b'>.\'_,?;:+-='


class CompressionRatioSideChannelAttack(object):
    def __init__(self, oracle, alphabet=alphabet, padding_chars=padding_chars, block_size=16):
        self.oracle = oracle
        self.block_size = block_size
        self.alphabet = alphabet
        self.padding_chars = padding_chars


    def execute(self, known_plaintext, secret_len):
        plaintext = known_plaintext
        extra_spaces = b' ' * self.block_size * 4

        for pos in range(secret_len - len(known_plaintext)):
            request_lengths = {}
            # padding = self._find_padding((plaintext + b'~' + extra_spaces) * (self.block_size // 2))
            padding = self._find_padding((plaintext + b'z' + b'z' * self.block_size * 4) * (self.block_size // 2))

            for curr_byte in self.alphabet:
                as_byte = struct.pack('B', curr_byte)
                payload = plaintext + as_byte

                #print(padding)
                # new_length = self.oracle.request(padding + (payload + extra_spaces) * (self.block_size // 2))
                new_length = self.oracle.request(padding + (payload + b'z' * self.block_size * 4) * (self.block_size // 2))
                request_lengths[as_byte] = new_length

            sorted_lengths = sorted(request_lengths.items(), key=lambda item: item[1])
            plaintext += sorted_lengths[0][0]

            if sorted_lengths[0][1] == sorted_lengths[1][1]:
                log.warning('Multiple best answers found')
        return plaintext


    def _find_padding(self, payload):
        # Unlikely characters. NOTE: Since we only include each character once
        # (to prevent compression), we need a suitable number of characters to actually
        # "pad" the CBC block to force it over a byte boundary. Sixteen should always work
        # for 16-byte blocks (e.g. AES-128).
        #possible_padding = ')(\{\}\\[]<%@#^`~$*!|`'[::-1].encode() + b'>.\'_,?;:+-='
        padding = b''

        log.debug('Attempting to find suitable padding')

        original_length = self.oracle.request(payload)

        for char in self.padding_chars:
            padding += struct.pack('B', char)

            if self.oracle.request(padding + payload) > original_length:
                log.debug('Found padding: {}'.format(padding.decode()))
                return padding
        raise Exception("Couldn't find a suitable padding")