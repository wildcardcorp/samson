from samson.hashes.keccak import Keccak
from samson.core.primitives import Primitive
from samson.core.metadata import SizeSpec, SizeType, FrequencyType
from samson.ace.decorators import register_primitive

class SHA3(Keccak):
    """
    Contains various SHA3 functions.
    """

    USAGE_FREQUENCY = FrequencyType.NORMAL

    def __init__(self, r: int, c: int, bits: int, padding: int):
        """
        Parameters:
            r       (int): The block size of the Keccak function.
            c       (int): The capacity of the Keccak function.
            bits    (int): The bits of output for the Keccak function.
            padding (int): The SHA3, domain-specific padding number.
        """
        super().__init__(r, c, bits)
        self.padding = padding


    def pad(self, in_bytes: bytes) -> bytes:
        bit_rate_bytes = (self.r + 7) // 8
        pad_len = bit_rate_bytes - (len(in_bytes) % bit_rate_bytes)

        if pad_len == 0:
            pad_len = bit_rate_bytes

        if pad_len == 1:
            return in_bytes + bytes([self.padding + 0x80])
        else:
            return in_bytes + bytes([self.padding] + ([0] * (pad_len - 2)) + [0x80])



@register_primitive()
class SHA3_224(SHA3):

    OUTPUT_SIZE = SizeSpec(size_type=SizeType.SINGLE, sizes=224)

    def __init__(self):
        super().__init__(r=1152, c=448, bits=224, padding=0x06)
        Primitive.__init__(self)


@register_primitive()
class SHA3_256(SHA3):

    OUTPUT_SIZE = SizeSpec(size_type=SizeType.SINGLE, sizes=256)

    def __init__(self):
        super().__init__(r=1088, c=512, bits=256, padding=0x06)
        Primitive.__init__(self)


@register_primitive()
class SHA3_384(SHA3):

    OUTPUT_SIZE = SizeSpec(size_type=SizeType.SINGLE, sizes=384)

    def __init__(self):
        super().__init__(r=832, c=768, bits=384, padding=0x06)
        Primitive.__init__(self)


@register_primitive()
class SHA3_512(SHA3):

    OUTPUT_SIZE = SizeSpec(size_type=SizeType.SINGLE, sizes=512)

    def __init__(self):
        super().__init__(r=576, c=1024, bits=512, padding=0x06)
        Primitive.__init__(self)


@register_primitive()
class SHAKE128(SHA3):

    OUTPUT_SIZE = SizeSpec(size_type=SizeType.ARBITRARY, typical=[128])

    def __init__(self, digest_bit_length: int):
        """
        Parameters:
            digest_bit_length (int): Desired digest length in bits.
        """
        super().__init__(r=1344, c=256, bits=digest_bit_length, padding=0x1F)
        Primitive.__init__(self)


@register_primitive()
class SHAKE256(SHA3):

    OUTPUT_SIZE = SizeSpec(size_type=SizeType.ARBITRARY, typical=[256])

    def __init__(self, digest_bit_length: int):
        """
        Parameters:
            digest_bit_length (int): Desired digest length in bits.
        """
        super().__init__(r=1088, c=512, bits=digest_bit_length, padding=0x1F)
        Primitive.__init__(self)
