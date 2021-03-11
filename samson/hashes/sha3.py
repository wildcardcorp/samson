from samson.hashes.keccak import Keccak
from samson.core.primitives import Primitive
from samson.core.metadata import SizeSpec, SizeType, FrequencyType
from samson.ace.decorators import register_primitive
from samson.utilities.bytes import Bytes


@register_primitive()
class SHA3_224(Keccak):

    OUTPUT_SIZE = SizeSpec(size_type=SizeType.SINGLE, sizes=224)

    def __init__(self):
        super().__init__(r=1152, c=448, digest_bit_size=224, padding=0x06)
        Primitive.__init__(self)


@register_primitive()
class SHA3_256(Keccak):

    OUTPUT_SIZE = SizeSpec(size_type=SizeType.SINGLE, sizes=256)

    def __init__(self):
        super().__init__(r=1088, c=512, digest_bit_size=256, padding=0x06)
        Primitive.__init__(self)


@register_primitive()
class SHA3_384(Keccak):

    OUTPUT_SIZE = SizeSpec(size_type=SizeType.SINGLE, sizes=384)

    def __init__(self):
        super().__init__(r=832, c=768, digest_bit_size=384, padding=0x06)
        Primitive.__init__(self)


@register_primitive()
class SHA3_512(Keccak):

    OUTPUT_SIZE = SizeSpec(size_type=SizeType.SINGLE, sizes=512)

    def __init__(self):
        super().__init__(r=576, c=1024, digest_bit_size=512, padding=0x06)
        Primitive.__init__(self)


@register_primitive()
class SHAKE128(Keccak):

    OUTPUT_SIZE = SizeSpec(size_type=SizeType.ARBITRARY, typical=[128])

    def __init__(self, digest_bit_length: int):
        """
        Parameters:
            digest_bit_length (int): Desired digest length in bits.
        """
        super().__init__(r=1344, c=256, digest_bit_size=digest_bit_length, padding=0x1F)
        Primitive.__init__(self)


@register_primitive()
class SHAKE256(Keccak):

    OUTPUT_SIZE = SizeSpec(size_type=SizeType.ARBITRARY, typical=[256])

    def __init__(self, digest_bit_length: int):
        """
        Parameters:
            digest_bit_length (int): Desired digest length in bits.
        """
        super().__init__(r=1088, c=512, digest_bit_size=digest_bit_length, padding=0x1F)
        Primitive.__init__(self)



class cSHAKE(Keccak):
    """
    References:
        https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-185.pdf
    """

    def __init__(self, r: int, c: int, digest_bit_length: int, w: int, function_name: bytes, customization_str: bytes):
        super().__init__(r=r, c=c, digest_bit_size=digest_bit_length, padding=0x1F)
        self.function_name = function_name
        self.customization_str = customization_str
        self.w = w
        self.padding = 0x04 if self.function_name or self.customization_str else 0x1F


    def _encode(self, x: int, left_encode: bool=True) -> Bytes:
        n   = max(x.bit_length(), 1)
        n  += -n % 8
        n //= 8

        left, right = [], []
        len_enc     = [n]

        if left_encode:
            left = len_enc
        else:
            right = len_enc

        return Bytes(left) + Bytes(x) + Bytes(right)


    def left_encode(self, x: int) -> Bytes:
        return self._encode(x, left_encode=True)


    def right_encode(self, x: int) -> Bytes:
        return self._encode(x, left_encode=False)


    def encode_string(self, message: bytes) -> bytes:
        return self.left_encode(len(message)*8) + message


    def bytepad(self, message: bytes) -> Bytes:
        return (self.left_encode(self.w) + message).pad_congruent_right(self.w)
    

    def pad(self, message: bytes) -> Bytes:
        if self.function_name or self.customization_str:
            padded = self.bytepad(self.encode_string(self.function_name) + self.encode_string(self.customization_str)) + message
            return super().pad(padded)

        else:
            return super().pad(message)


@register_primitive()
class cSHAKE128(cSHAKE):
    def __init__(self, digest_bit_length: int, function_name: bytes=b'', customization_str: bytes=b''):
        """
        Parameters: 
            digest_bit_length   (int): Desired digest length in bits.
            function_name     (bytes): NIST function string.
            customization_str (bytes): User defined string.
        """
        super().__init__(r=1344, c=256, digest_bit_length=digest_bit_length, w=168, function_name=function_name, customization_str=customization_str)
        Primitive.__init__(self)


@register_primitive()
class cSHAKE256(cSHAKE):
    def __init__(self, digest_bit_length: int, function_name: bytes=b'', customization_str: bytes=b''):
        """
        Parameters: 
            digest_bit_length   (int): Desired digest length in bits.
            function_name     (bytes): NIST function string.
            customization_str (bytes): User defined string.
        """
        super().__init__(r=1088, c=512, digest_bit_length=digest_bit_length, w=136, function_name=function_name, customization_str=customization_str)
        Primitive.__init__(self)
