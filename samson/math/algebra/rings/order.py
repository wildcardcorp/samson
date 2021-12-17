from samson.math.algebra.rings.ring import Ring, RingElement
from samson.math.algebra.rings.integer_ring import ZZ
from samson.math.general import hilbert_class_polynomial, is_prime, product, cyclomotic_polynomial, cornacchias_algorithm
from samson.math.symbols import Symbol, oo
from samson.math.factorization.general import factor, Factors
from samson.math.matrix import Matrix
from samson.utilities.exceptions import NoSolutionException


class OrderElement(RingElement):
    def __init__(self, val: RingElement, ring: Ring):
        super().__init__(ring)
        self.val = val


    def __reprdir__(self):
        return ['val', 'ring']


    def __neg__(self) -> 'OrderElement':
        return self.__class__(-self.val, self.ring)


    def is_prime(self) -> bool:
        p = self.val.val
        K = self.ring

        if self in [K(0), K(1)]:
            return False

        if p.degree():
            return p.is_irreducible()
        else:
            n = int(p[0])
            if not n % K.discriminant():
                return False

            return is_prime(abs(n)) and K.defining_polynomial.change_ring(ZZ/ZZ(abs(n))).is_irreducible()


    is_irreducible = is_prime


    def factor(self) -> 'Factors':
        """
        References:
            https://math.stackexchange.com/questions/1033901/prime-ideals-of-the-ring-of-integers-of-an-algebraic-number-field
            https://cstheory.stackexchange.com/questions/16214/complexity-of-factoring-in-number-fields
        """
        K = self.ring

        if self in (K.zero, K.one) or self.is_prime():
            return Factors({self: 1})

        m = self.val.val
        d = m.degree()

        if d:
            m_facs  = m.factor()
            factors = Factors()

            for fac, e in m_facs.items():
                k_fac = K(fac)

                if k_fac.val.val.degree():
                    factors.add(k_fac)
                else:
                    factors += k_fac.factor()**e

            return factors


        n = int(m[0])

        # K(n) can only be prime if `n` is
        # Note the converse is not true i.e. 11 may not be prime in K
        if is_prime(abs(n)):
            negate = False
            if n < 0:
                negate = True
                n = -n


            if not n % K.discriminant():
                facs = {K.symbol*1: K.degree()}

                if n // K.discriminant() < 0:
                    facs[K(-1)] = 1

                return Factors(facs)
            

            q = K.defining_polynomial.change_ring(ZZ/ZZ(n))

            if q.is_irreducible():
                factors = Factors({K(n): 1})

                if negate:
                    factors.add(K(-1))
                
                return factors


            facs = q.factor()

            K_facs = [f.change_ring(ZZ)(K.symbol) for f in facs.expand()]
            for i in range(2**K.degree()):
                candidates = [k+n*-int(b) for k,b in zip(K_facs, bin(i)[2:].zfill(K.degree()))]
                prod = product(candidates)

                if prod in [K(n), -K(n)]:
                    facs = Factors()
                    if (prod == -K(n)) ^ negate:
                        candidates.append(K(-1))

                    for cand in candidates:
                        facs.add(cand)
                    return facs


        else:
            neg_one = K(-1)
            if n == -1:
                return Factors({neg_one: 1})

            facs = Factors()
            for p, e in factor(n).items():
                facs += K(p).factor()**e
            

            if neg_one in facs:
                facs[neg_one] %= 2

                if not facs[neg_one]:
                    del facs.factors[neg_one]


            return facs


    def __iter__(self):
        z = ZZ.zero
        d = self.ring.degree()
        n = self.val.val.degree()+1

        for c in (list(self.val.val) + [z]*(d-n)):
            yield c


    def matrix(self) -> Matrix:
        cur = Matrix([list(self)])
        X   = self.ring.generator_matrix()
        v   = [list(cur)[0]]

        for _ in range(self.ring.degree()-1):
            cur *= X
            v   += [list(cur)[0]]

        return Matrix(v)


    def is_rational(self) -> bool:
        return not self.val.val.degree()


    def minimum_polynomial(self) -> 'Polynomial':
        if self.is_rational():
            x = Symbol('x')
            _ = ZZ[x]
            return x - list(self)[0]
        
        else:
            return self.matrix().characteristic_polynomial()


    def norm(self) -> RingElement:
        return self.matrix().det()


    def trace(self) -> RingElement:
        return self.matrix().trace()
    

    # def __elemfloordiv__(self, other: 'RingElement') -> 'RingElement':
       
    #     if self.is_rational() and other.is_rational():
    #         return self.ring(self.val // other.val)
    #     else:
    #         sf = self.factor()
    #         of = other.factor()




    def gcd(self, other: 'OrderElement') -> 'OrderElement':
        R = self.ring

        if R.is_field():
            return R.one
        elif self.is_rational() and other.is_rational():
            return self.val.gcd(other.val)
        else:
            return R(self.factor().gcd(other.factor()).recombine())




class Order(Ring):
    ELEMENT_TYPE = OrderElement

    def __init__(self, defining_polynomial: 'Polynomial'):
        if not defining_polynomial.is_irreducible():
            raise ValueError(f"{defining_polynomial} is not irreducible")

        self.defining_polynomial = defining_polynomial
        self.symbol          = defining_polynomial.symbol
        self.internal_ring   = ZZ[self.symbol]/self.defining_polynomial
        self.symbol.top_ring = self

        self.one  = self.ELEMENT_TYPE(self.internal_ring.one, self)
        self.zero = self.ELEMENT_TYPE(self.internal_ring.zero, self)


    def __reprdir__(self):
        return ['defining_polynomial']


    def __hash__(self) -> int:
        return hash((self.internal_ring, self.__class__))


    def shorthand(self) -> str:
        return f'ZZ[{self.symbol}]'


    def characteristic(self) -> int:
        return 0


    def order(self) -> int:
        return oo


    def is_superstructure_of(self, R: 'Ring') -> bool:
        """
        Determines whether `self` is a superstructure of `R`.

        Parameters:
            R (Ring): Possible substructure.

        Returns:
            bool: Whether `self` is a superstructure of `R`.
        """
        return self.internal_ring.is_superstructure_of(R)


    def coerce(self, other: object) -> OrderElement:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (object): Object to coerce.

        Returns:
            OrderElement: Coerced element.
        """
        if not type(other) is self.ELEMENT_TYPE:
            other = self.ELEMENT_TYPE(self.internal_ring(other), self)

        return other


    def element_at(self, x: int) -> OrderElement:
        """
        Returns the `x`-th element of the set.

        Parameters:
            x (int): Element ordinality.

        Returns:
           OrderElement: The `x`-th element.
        """
        return self.ELEMENT_TYPE(self.internal_ring.element_at(x), self)


    def random(self, size: OrderElement=None) -> OrderElement:
        if size is not None:
            size = size.val
        return self(self.internal_ring.random(size))


    def __eq__(self, other: 'NumberField') -> bool:
        return type(self) == type(other) and self.internal_ring == other.internal_ring


    def is_field(self) -> bool:
        return False


    def degree(self) -> int:
        return self.defining_polynomial.degree()


    def discriminant(self) -> int:
        raise NotImplementedError


    def generator_matrix(self) -> Matrix:
        x = self.symbol
        a = x
        d = self.degree()
        v = [list((x*1))]

        for _ in range(d-1):
            a *= x
            v += [list(a)]
        
        return Matrix(v)



class QuadraticFieldElement(OrderElement):
    def factor(self) -> Factors:
        """
        References:
            https://math.stackexchange.com/questions/1043480/how-to-factor-ideals-in-a-quadratic-number-field
        """
        p = self.val.val
        K = self.ring

        facs = super().factor()
        if facs is None and K.discriminant() % 4 == 1 and int(p[0]) == 2:
            Q = K.fraction_field()
            Q.simplify = False
            print('Here')
            return Factors({Q(((1 + K.symbol), 2)): 1, Q(((1 + -K.symbol), 2)): 1})
        else:
            return facs


    def conjugate(self) -> 'OrderElement':
        p = self.val.val
        return self.ring(p[0] + -p[1]*self.ring.symbol)


    def is_prime(self) -> bool:
        """
        References:
            https://kconrad.math.uconn.edu/blurbs/gradnumthy/quadraticgrad.pdf
        """
        if abs(self.norm()).is_prime():
            return True
        
        x = Symbol('x')
        ZZ[x]

        d = self.ring.discriminant()
        if d % 4 == 1:
            f = x**2 - x + (1-d) // 4
        else:
            f = self.ring.defining_polynomial


        # base_result = super().is_prime()

        # if base_result or not self.is_rational():
        #     return base_result
        
        if self.is_rational():
            p = abs(int(self.val.val[0]))
            return f.change_ring(ZZ/ZZ(p)).is_irreducible()
        else:
            return super().is_prime()


        try:
            cornacchias_algorithm(-d, 4*p)
            return False
        except NoSolutionException:
            pass

        try:
            cornacchias_algorithm(-d, p)
            return False
        except NoSolutionException:
            return True


class QuadraticField(Order):
    ELEMENT_TYPE = QuadraticFieldElement

    def __init__(self, D: int, symbol_name: str=None) -> 'Order':
        if ZZ(D).is_square():
            raise ValueError(f'"D" ({D}) cannot be square')
        
        if not symbol_name:
            symbol_name = f'√{D}'

        x = Symbol(symbol_name)
        ZZ[x]

        super().__init__(x**2 - D)


    def discriminant(self) -> int:
        D = ZZ(self.defining_polynomial.discriminant())
        d = factor(int(D)).square_free().recombine()

        if d % 4 != 1:
            d *= 4
        
        return d


    def hilbert_class_polynomial(self) -> 'Polynomial':
        disc = self.discriminant()

        if disc > 0:
            raise ValueError('Discriminant cannot be positive')

        return hilbert_class_polynomial(int(disc))



class CyclotomicField(Order):
    def __init__(self, n: int) -> 'Order':
        self.n = n
        super().__init__(cyclomotic_polynomial(n))


    def discriminant(self) -> int:
        """
        References:
            https://math.stackexchange.com/questions/240651/the-discriminant-of-the-cyclotomic-phi-px
            https://github.com/sagemath/sage/blob/a60179ab6b642246ee54120e43fdf9663afe5638/src/sage/rings/number_field/number_field.py#L11319
        """
        deg     = self.defining_polynomial.degree()
        d       = 1
        factors = factor(self.n)

        for (p, r) in factors.items():
            e = (r*p - r - 1) * deg // (p-1)
            d *= p**e

        sign = 1

        if len(factors) == 1 and (self.n == 4 or list(factors)[0] % 4 == 3):
            sign = -1
        elif len(factors) == 2 and list(factors.items())[0] == (2, 1) and list(factors)[1] % 4 == 3:
            sign = -1

        return sign*d
