from sympy import Poly

class FLFSR(object):
    def __init__(self, seed, polynomial):
        self.state = seed

        if type(polynomial) is Poly:
            polynomial = int(''.join(str(coeff) for coeff in polynomial.all_coeffs()), 2)

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



    def clock(self):
        self.state <<= 1

        lsb = sum([int(bit) for bit in bin(self.state & self.polynomial)[2:]]) % 2
        self.state |= lsb
        self.state &= 0xFFFFFFFFFFFFFFFF
        return self.state & self.mask