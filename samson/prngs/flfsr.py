from sympy import Poly
from samson.utilities.encoding import poly_to_int
from samson.prngs.glfsr import GLFSR

class FLFSR(GLFSR):
    """
    Fibonacci linear-feedback shift register.
    """

    def __init__(self, seed: int, polynomial: Poly):
        """
        Parameters:
            seed        (int): Initial value.
            polynomial (Poly): Either a `sympy` `Poly` or an integer that represents the polynomal.
        """
        self.state = seed

        if type(polynomial) is Poly:
            polynomial = poly_to_int(polynomial)

        self.polynomial = polynomial
        self.mask = 1
        self.wrap_around_mask = 2 ** (polynomial.bit_length()) - 1
        self.state &= self.wrap_around_mask


        poly_mask = polynomial
        while poly_mask:
            if poly_mask & self.mask:
                poly_mask ^= self.mask

            if not poly_mask:
                break

            self.mask <<= 1

        self.mask -= 1



    def __repr__(self):
        return f"<FLFSR: state={self.state}, polynomial={self.polynomial}, mask={self.mask}>"

    def __str__(self):
        return self.__repr__()



    def clock(self) -> int:
        """
        Generates the next psuedorandom output.

        Returns:
            int: Next psuedorandom output.
        """
        self.state <<= 1

        lsb = sum([int(bit) for bit in bin(self.state & self.polynomial)[2:]]) % 2
        self.state |= lsb
        self.state &= 0xFFFFFFFFFFFFFFFF
        return self.state & 1



    def reverse_clock(self, output: int):
        """
        Clocks the state in reverse given the previous output.

        Parameters:
            output (int): Previous output.
        """
        raise NotImplementedError()



    def generate(self) -> int:
        """
        Calls self.clock(). Here for interface uniformity.

        Returns:
            int: Next psuedorandom output.
        """
        return self.clock()
