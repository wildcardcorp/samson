from samson.prngs.bitsliced_flfsr import BitslicedFLFSR
from samson.utilities.bytes import Bytes

# https://github.com/ttsou/airprobe/blob/master/A5.1/python/A51_Tables/a51.py
# Implemented in big endian
class A51(object):
    """
    A5/1 stream cipher

    Used in GSM celluar encryption.
    """

    def __init__(self, key: bytes, frame_num: int):
        """
        Parameters:
            key     (bytes): Key (64 bits).
            frame_num (int): Current frame number (22 bits).
        """
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



    def __repr__(self):
        return f"<A51: key={self.key}, frame_num={self.frame_num}, lfsr_regs={self.lfsr_regs}>"

    def __str__(self):
        return self.__repr__()



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
