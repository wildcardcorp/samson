from sympy import Poly
from samson.utilities.math import berlekamp_massey

class GLFSR(object):
    def __init__(self, seed, polynomial):
        self.state = seed

        if type(polynomial) is Poly:
            polynomial = int(''.join(str(coeff) for coeff in polynomial.all_coeffs()), 2)

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
        self.state <<= 1
        self.state &= self.wrap_around_mask

        if self.state & self.mask:
            self.state ^= self.polynomial
            return 1

        else:
            return 0
        

    
    def reverse_clock(self, output):
        for item in output:
            if item:
                self.state ^= self.polynomial
            
            self.state >>=1
            self.state &= self.wrap_around_mask



    # TODO: Make work with arbitrary polynomials!
    @staticmethod
    def crack(output):
        # Find minimum polynomial that represents the output
        poly = berlekamp_massey(output)

        # Create new LFSR and clock in reverse
        lfsr = GLFSR(0, poly)
        lfsr.reverse_clock(output[::-1])

        # Clock forward to synchronize with output
        [(lfsr.clock(), lfsr.state) for i in range(len(output))]

        return lfsr