from sympy import Poly
from samson.utilities.math import berlekamp_massey

class GLFSR(object):
    def __init__(self, seed, polynomial):
        self.state = seed

        if type(polynomial) is Poly:
            polynomial = GLFSR.poly_to_int(polynomial)
            #polynomial = int(''.join(str(coeff) for coeff in polynomial.all_coeffs()), 2)

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
        while True:
            self.state <<= 1
            self.state &= self.wrap_around_mask

            if self.state & self.mask:
                self.state ^= self.polynomial
                return 1

            else:
                return 0


    @staticmethod
    def poly_to_int(polynomial):
        return int(''.join(str(coeff) for coeff in polynomial.all_coeffs()), 2)



    # TODO: Make work with arbitrary polynomials!
    @staticmethod
    def crack(output):
        # Find minimum polynomial that represents the output
        poly = berlekamp_massey(output)
        L = len(poly.all_coeffs())

        
        # Emulate several XORs of the polynomial mask
        poly_int = GLFSR.poly_to_int(poly)
        poly_mask = 0
        for i in range(L):
            poly_mask ^= poly_int << i

        print(poly_mask)
        # Use last `L` inputs to construct the state `L - 1` clocks ago
        output_as_int = int(''.join([str(bit) for bit in output[-L:]]), 2)
        lfsr = GLFSR(output_as_int ^ poly_mask, poly)

        # Clock `L - 1` times to synchronize
        [(lfsr.clock(), lfsr.state) for i in range(L - 1)]
        return lfsr