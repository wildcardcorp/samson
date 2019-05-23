from samson.math.algebra.rings.ring import Ring

class Polynomial(object):
    def __init__(self, coeffs: list, ring: Ring=None):
        self.ring = ring or coeffs[0].ring

        coeffs_rev = coeffs[::-1]
        idx = 0
        while idx < len(coeffs) - 1 and coeffs_rev[idx] == self.ring.zero():
            idx += 1

        self.coeffs = coeffs_rev[idx:][::-1]

    

    def shorthand(self) -> str:
        poly_repr = []
        for idx, coeff in enumerate(self.coeffs):
            if coeff == coeff.ring.zero() and not len(self.coeffs) == 1:
                continue
            
            if coeff == coeff.ring.one() and idx != 0:
                coeff_short_mul = ''
            else:
                coeff_short_mul = coeff.shorthand() + '*'

            if idx == 0:
                full_coeff = f'{coeff_short_mul[:-1]}'
            elif idx == 1:
                full_coeff = f'{coeff_short_mul}x'
            else:
                full_coeff = f'{coeff_short_mul}x**{idx}'
            
            poly_repr.append(full_coeff)

        return ' + '.join(poly_repr[::-1])


    def __repr__(self):
        return f"<Polynomial: {self.shorthand()}, ring={self.ring}>"


    def __str__(self):
        return self.__repr__()
    

    def LC(self) -> object:
        return self.coeffs[-1]
    

    def evalulate(self, x: int) -> object:
        return sum([coeff*(x**idx) for idx, coeff in enumerate(self.coeffs)])
    

    def monic(self) -> object:
        return Polynomial([coeff / self.coeffs[-1] for coeff in self.coeffs], self.ring)
    

    def is_monic(self) -> bool:
        return self.LC == self.ring.one()


    def derivative(self) -> object:
        return Polynomial([coeff * idx for idx, coeff in enumerate(self.coeffs)][1:], self.ring)
    

    def degree(self) -> int:
        return len(self.coeffs) - 1
    

    def pad(self, length: int) -> list:
        return self.coeffs + [self.ring.zero()] * (length - len(self.coeffs))


    def pad_and_zip(self, other: object) -> list:
        pad_len = max(len(self.coeffs), len(other.coeffs))
        return zip(self.pad(pad_len), other.pad(pad_len))
    

    def divmod(self, divisor: object) -> (object, object):
        poly_zero = Polynomial([self.ring.zero()])
        assert divisor != poly_zero

        q = poly_zero
        remainder = self

        while remainder != poly_zero and remainder.degree() >= divisor.degree():
            pad_len = len(remainder.coeffs) - len(divisor.coeffs)
            t  = Polynomial([self.ring.zero()] * pad_len + [remainder.LC() // divisor.LC()])
            q += t
            remainder = remainder - t * divisor

        return (q, remainder)


    def __add__(self, other: object) -> object:
        return Polynomial([a + b for a,b in self.pad_and_zip(other)], self.ring)

    def __sub__(self, other: object) -> object:
        return Polynomial([a - b for a,b in self.pad_and_zip(other)], self.ring)

    def __mul__(self, other: object) -> object:
        new_coeff_len = max((len(self.coeffs) * len(other.coeffs) - 1), len(self.coeffs) + len(other.coeffs))
        new_coeffs    = [self.ring.zero()] * new_coeff_len

        for i, coeff_h in enumerate(self.coeffs):
            for j, coeff_g in enumerate(other.coeffs):
                new_coeffs[i+j] += coeff_h*coeff_g

        return Polynomial(new_coeffs, self.ring)

    def __neg__(self) -> object:
        return Polynomial([-coeff for coeff in self.coeffs], self.ring)
    
    
    def __truediv__(self, other: object) -> object:
        return self.divmod(other)[0]

    def __mod__(self, other: object) -> object:
        return self.divmod(other)[1]