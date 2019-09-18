from samson.math.polynomial import Polynomial
from samson.math.general import berlekamp_massey
from samson.math.general import poly_to_int

class GLFSR(object):
    """
    Galois linear-feedback shift register.
    """

    def __init__(self, seed: int, polynomial: Polynomial):
        """
        Parameters:
            seed              (int): Initial value.
            polynomial (Polynomial): Either a `Polynomial` or an integer that represents the polynomal.
        """
        self.state = seed

        if type(polynomial) is Polynomial:
            polynomial = poly_to_int(polynomial)

        self.polynomial = polynomial
        self.mask = 1
        self.wrap_around_mask = 2 ** polynomial.bit_length() - 1
        self.state &= self.wrap_around_mask


        poly_mask = polynomial
        while poly_mask:
            if poly_mask & self.mask:
                poly_mask ^= self.mask

            if not poly_mask:
                break

            self.mask <<= 1


    def __repr__(self):
        return f"<GLFSR: state={self.state}, polynomial={self.polynomial}, mask={self.mask}>"


    def __str__(self):
        return self.__repr__()



    def clock(self):
        """
        Generates the next pseudorandom output.

        Returns:
            int: Next pseudorandom output.
        """
        self.state <<= 1
        self.state &= self.wrap_around_mask

        if self.state & self.mask:
            self.state ^= self.polynomial
            return 1

        else:
            return 0



    def generate(self) -> int:
        """
        Calls self.clock(). Here for interface uniformity
        
        Returns:
            int: Next pseudorandom output.
        """
        return self.clock()



    def reverse_clock(self, output: int):
        """
        Clocks the state in reverse given the previous output.

        Parameters:
            output (int): Previous output.
        """
        for item in output:
            if item:
                self.state ^= self.polynomial

            self.state >>=1
            self.state &= self.wrap_around_mask



    @staticmethod
    def crack(outputs: list):
        """
        Given a list of outputs, creates a GLFSR that generates the same sequence.

        Parameters:
            outputs (list): A list of outputs from the GLFSR (in order).
        
        Returns:
            GLFSR: GLFSR that generates the same sequence.
        """
        # Find minimum polynomial that represents the output
        poly = berlekamp_massey(outputs)

        # Create new LFSR and clock in reverse
        lfsr = GLFSR(0, poly)
        lfsr.reverse_clock(outputs[::-1])

        # Clock forward to synchronize with output
        [(lfsr.clock(), lfsr.state) for i in range(len(outputs))]

        return lfsr
