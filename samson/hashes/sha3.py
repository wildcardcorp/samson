from samson.hashes.keccak import Keccak

class SHA3(object):
    """
    Contains various SHA3 functions.
    """

    @staticmethod
    def build_sha3(r: int, c: int, bits: int, padding: int) -> Keccak:
        """
        Parameters:
            r       (int): The block size of the Keccak function.
            c       (int): The capacity of the Keccak function.
            bits    (int): The bits of output for the Keccak function.
            padding (int): The SHA3, domain-specific padding number.
        """
        k = Keccak(r, c, bits)

        def pad(in_bytes):
            bit_rate_bytes = (k.r + 7) // 8
            pad_len = bit_rate_bytes - (len(in_bytes) % bit_rate_bytes)

            if pad_len == 0:
                pad_len = bit_rate_bytes

            if pad_len == 1:
                return in_bytes + bytes([padding + 0x80])
            else:
                return in_bytes + bytes([padding] + ([0] * (pad_len - 2)) + [0x80])


        k.pad_func = pad
        return k


    @staticmethod
    def K224() -> Keccak:
        return SHA3.build_sha3(1152, 448, 224, 0x06)


    @staticmethod
    def K256() -> Keccak:
        return SHA3.build_sha3(1088, 512, 256, 0x06)


    @staticmethod
    def K384() -> Keccak:
        return SHA3.build_sha3(832, 768, 384, 0x06)


    @staticmethod
    def K512() -> Keccak:
        return SHA3.build_sha3(576, 1024, 512, 0x06)


    @staticmethod
    def SHAKE128(digest_bit_length: int) -> Keccak:
        return SHA3.build_sha3(1344, 256, digest_bit_length, 0x1F)


    @staticmethod
    def SHAKE256(digest_bit_length: int) -> Keccak:
        return SHA3.build_sha3(1088, 512, digest_bit_length, 0x1F)
