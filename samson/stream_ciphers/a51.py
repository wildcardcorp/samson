from samson.prngs.bitsliced_flfsr import BitslicedFLFSR
from samson.core.primitives import StreamCipher, Primitive
from samson.utilities.bytes import Bytes
from samson.core.metadata import ConstructionType, UsageType, SizeType, SizeSpec, EphemeralType, EphemeralSpec
from samson.ace.decorators import register_primitive

# https://github.com/ttsou/airprobe/blob/master/A5.1/python/A51_Tables/a51.py
# Implemented in big endian
@register_primitive()
class A51(StreamCipher):
    """
    A5/1 stream cipher

    Used in GSM celluar encryption.
    """

    CONSTRUCTION_TYPES = [ConstructionType.LFSR]
    USAGE_TYPE         = UsageType.CELLULAR
    KEY_SIZE           = SizeSpec(size_type=SizeType.SINGLE, sizes=64)
    EPHEMERAL          = EphemeralSpec(ephemeral_type=EphemeralType.NONCE, size=SizeSpec(size_type=SizeType.SINGLE, sizes=22))

    def __init__(self, key: bytes, frame_num: int):
        """
        Parameters:
            key     (bytes): Key (64 bits).
            frame_num (int): Current frame number (22 bits).
        """
        Primitive.__init__(self)

        self.key = key
        self.frame_num = frame_num

        self.lfsr_regs = [
            BitslicedFLFSR(19, 10, [13, 16, 17, 18]),
            BitslicedFLFSR(22, 11, [20, 21]),
            BitslicedFLFSR(23, 12, [7, 20, 21, 22])
        ]

        for lfsr in self.lfsr_regs:
            lfsr.mix_state(self.key, 64)
            lfsr.mix_state(self.frame_num, 22)

        for _ in range(100):
            self.clock()



    def clock(self):
        """
        Performs the majority-vote clocking.
        """
        majority = sum([lfsr.clock_value() for lfsr in self.lfsr_regs]) // 2

        for lfsr in self.lfsr_regs:
            if lfsr.clock_value() == majority:
                lfsr.clock()



    def generate(self, length: int) -> Bytes:
        """
        Generates `length` of keystream.

        Parameters:
            length (int): Desired length of keystream in bytes.
        
        Returns:
            Bytes: Keystream.
        """
        bitstring = ''
        for _ in range(length * 8):
            self.clock()
            bitstring += str(self.lfsr_regs[0].value() ^ self.lfsr_regs[1].value() ^ self.lfsr_regs[2].value())

        return Bytes(int(bitstring, 2)).zfill(length)
