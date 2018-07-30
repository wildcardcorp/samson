from samson.utilities import *
import string

alphabet = (string.ascii_lowercase + string.ascii_uppercase + string.digits + '=/+' + ':;').encode()



class CompressionRatioSideChannelAttack(object):
    def __init__(self, oracle, block_size=16):
        self.oracle = oracle
        self.block_size = block_size


    def execute(self, known_plaintext, secret_len):
        plaintext = known_plaintext
        extra_spaces = b' ' * self.block_size * 4

        for _ in range(secret_len - len(known_plaintext)):
            request_lengths = {}
            padding = self._find_padding((plaintext + b'~' + extra_spaces) * (self.block_size // 2))

            for curr_byte in alphabet:
                as_byte = struct.pack('B', curr_byte)
                payload = plaintext + as_byte

                #print(padding)
                new_length = self.oracle.request(padding + (payload + extra_spaces) * (self.block_size // 2))
                request_lengths[as_byte] = new_length

            plaintext += sorted(request_lengths.items(), key=lambda item: item[1])[0][0]
        return plaintext


    def _find_padding(self, payload):
        # Unlikely characters. NOTE: Since we only include each character once
        # (to prevent compression), we need a suitable number of characters to actually
        # "pad" the CBC block to force it over a byte boundary. Sixteen should always work
        # for 16-byte blocks (e.g. AES-128).
        possible_padding = ')(\{\}\\[]<%@#^`~$*!|`'[::-1].encode() + b'>.\'_,?;:+-=' #b''.join([struct.pack('B', i) for i in list(range(8)) + [11,12] + list(range(20,26))])
        padding = b''

        original_length = self.oracle.request(payload)

        for char in possible_padding:
            padding += struct.pack('B', char)

            if self.oracle.request(padding + payload) > original_length:
                return padding
        return b''