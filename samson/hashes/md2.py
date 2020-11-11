from samson.padding.pkcs7 import PKCS7
from samson.utilities.bytes import Bytes
from samson.constructions.merkle_damgard_construction import MerkleDamgardConstruction
from samson.core.primitives import Primitive
from samson.core.metadata import SizeSpec, SizeType
from samson.ace.decorators import register_primitive

# https://tools.ietf.org/html/rfc1319
# https://gist.github.com/CameronLonsdale/23772092aa4e0c75f2426eb418b156e6

_pkcs7 = PKCS7(16)

PI_SUBST = [
    41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
  19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
  76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
  138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
  245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
  148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
  39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
  181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
  150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
  112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
  96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
  85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
  234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
  129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
  8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
  203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
  166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
  31, 26, 219, 153, 141, 51, 159, 17, 131, 20
]

ROUNDS = 18

def compression_func(block: bytes, state: bytes) -> Bytes:
    digest    = state + block + (state ^ block)
    prev_byte = 0

    for j in range(ROUNDS):
        for k in range(48):
            digest[k] = prev_byte = digest[k] ^ PI_SUBST[prev_byte]

        prev_byte = (prev_byte + j) % 256

    return digest[:16]


@register_primitive()
class MD2(MerkleDamgardConstruction):

    OUTPUT_SIZE = SizeSpec(size_type=SizeType.SINGLE, sizes=128)

    def __init__(self, initial_state: bytes=b'\x00'*16):
        """
        Parameters:
            initial_state (bytes): (Optional) Initial internal state.
        """
        super().__init__(
            initial_state=initial_state,
            compression_func=compression_func,
            block_size=16,
            digest_size=16,
            endianness='little'
        )

        Primitive.__init__(self)


    def __reprdir__(self):
        return ['initial_state', 'block_size']


    @staticmethod
    def checksum(message: bytes) -> Bytes:
        message  = Bytes.wrap(message)
        checksum = Bytes().zfill(16)

        previous_checkbyte = 0

        for chunk in message.chunk(16):
            for idx, char in enumerate(chunk):
                previous_checkbyte = checksum[idx] = checksum[idx] ^ PI_SUBST[char ^ previous_checkbyte]

        return checksum


    def pad_func(self, message: bytes) -> Bytes:
        message  = _pkcs7.pad(message)
        message += MD2.checksum(message)
        return message
