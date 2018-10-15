from samson.hashes.keccak import Keccak

class SHA3(object):
    @staticmethod
    def _build_sha3(r, c, bits):
        k = Keccak(r, c, bits)

        def pad(in_bytes):
            bit_rate_bytes = (k.r + 7) // 8
            pad_len = bit_rate_bytes - (len(in_bytes) % bit_rate_bytes)

            if pad_len == 0:
                pad_len = bit_rate_bytes

            if pad_len == 1:
                return in_bytes + bytes([0x86])
            else:
                return in_bytes + bytes([0x06] + ([0] * (pad_len - 2)) + [0x80])

        
        k.pad_func = pad
        return k


    @staticmethod
    def K224():
        return SHA3._build_sha3(1152, 448, 224)


    @staticmethod
    def K256():
        return SHA3._build_sha3(1088, 512, 256)


    @staticmethod
    def K384():
        return SHA3._build_sha3(832, 768, 384)


    @staticmethod
    def K512():
        return SHA3._build_sha3(576, 1024, 512)