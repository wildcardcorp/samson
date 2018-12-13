from samson.utilities.bitstring import Bitstring

class BitslicedFLFSR(object):
    """
    An implementation of an FLFSR using an internal bitstring rather than an integer.
    """

    def __init__(self, length: int, clock_bit: int, taps: list, seed: int=0):
        """
        Parameters:
            length    (int): Length of the internal, bitstring state.
            clock_bit (int): Bit considered to be the 'clock' bit.
            taps     (list): Positional taps used to determine the next bit.
            seed      (int): Inital state represented as an integer.
        """
        self.state = bin(seed)[2:].zfill(length)
        self.length = length
        self.clock_bit = clock_bit
        self.taps = taps


    def __repr__(self):
        return f"<BitslicedFLFSR: state={self.state}, length={self.length}, clockbit={self.clock_bit}, taps={self.taps}>"


    def __str__(self):
        return self.__repr__()


    def mix_state(self, in_val: bytes, size: int):
        """
        Mixes state into the FLSFR by clocking in each bit.

        Parameters:
            in_val (bytes): Bytes-like value to clock in.
            size     (int): Size for the bitstring to be padded to.
        """
        bit_val = Bitstring.wrap(in_val).zfill(size)

        for bit in str(bit_val)[::-1]:
            self.clock(int(bit))


    def clock(self, bit: int=0):
        """
        Clocks the FLSFR with an optional input value.

        Parameters:
            bit (int): (Optional) Value to XOR'd in with the next bit.
        """
        for tap in self.taps:
            position = self.length - tap - 1
            bit ^= int(self.state[position])

        self.state += '0'
        self.state = self.state[1:]
        self.state = (self.state[:self.length - 1] + str(bit))


    def value(self) -> int:
        """
        Retrives the current value in state[0].

        Returns:
            int: Current value.
        """
        return int(self.state[0])


    def clock_value(self) -> int:
        """
        Retrives the value in state[clock_bit].

        Returns:
            int: Clock value.
        """
        return int(self.state[self.clock_bit])



    def generate(self) -> int:
        """
        Calls self.clock(). Here for interface uniformity.

        Returns:
            int: Current value.
        """
        self.clock()
        return self.value()
