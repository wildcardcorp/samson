from samson.math.general import is_primitive_root, find_prime, is_safe_prime, is_sophie_germain_prime, next_prime, is_prime
from samson.math.factorization.factors import Factors
from samson.utilities.exceptions import SearchspaceExhaustedException
from samson.auxiliary.roca import gen_roca_prime
import math

class PGen(object):
    def __init__(self, size: int):
        self.size = size

    def generate(self, constraints: list=None) -> int:
        for p in self.generate_many(constraints=constraints):
            return p


    def generate_many(self, constraints: list=None) -> list:
        p = 1
        constraints = constraints or []
        gen = self._gen(constraints)

        try:
            while True:
                while not (is_prime(p) and p.bit_length() == self.size and all([c(p) for c in constraints])):
                    p = gen.__next__()

                yield p
                p = 1
        except StopIteration:
            raise SearchspaceExhaustedException



class RandGen(PGen):
    def _gen(self, constraints: list):
        while True:
            yield find_prime(self.size)


class ROCAGen(PGen):
    def __init__(self, size: int):
        if size < 256:
            raise ValueError('Cannot generate ROCA primes under 256 bits')

        self.size = size


    def _gen(self, constraints: list):
        while True:
            p, _, _, _ = gen_roca_prime(self.size)
            yield p


class SmoothGen(PGen):
    def __init__(self, size: int, base: int=2, glue_prime_exclude: set=None, max_glue_size :int=16, distance: int=1):
        self.size = size
        self.base = base
        self.glue_prime_exclude = set(glue_prime_exclude or [])
        self.max_glue_size = max_glue_size
        self.distance = distance


    def _gen(self, constraints: list):
        facs  = Factors({self.base: int(math.log(2**(self.size-1), self.base))})
        facs += {2: 1}

        for i in range(facs[self.base]):
            p_1       = (facs - {self.base:i}).recombine()
            glue_size = self.size - p_1.bit_length() + 1

            # No odd prime this small
            if glue_size < 2:
                continue

            # If we reach 'max_glue_size', we should tack on the smallest prime possible and retry.
            # This should work as well as any other method assuming primes are uniformly distributed
            if glue_size > self.max_glue_size:
                p = next_prime(self.base+1)
                while p in self.glue_prime_exclude:
                    p = next_prime(p+1)

                facs     += {p: 1}
                p_1       = (facs - {self.base:i}).recombine()
                glue_size = self.size - p_1.bit_length() + 1


            # Try all primes of this bit length
            p = next_prime(2**(glue_size-1))

            while p.bit_length() == glue_size:
                q = p_1*p+self.distance
                if is_prime(q):
                    yield q


                p = next_prime(p+1)
                while p in self.glue_prime_exclude:
                    p = next_prime(p+1)



class CongruentGen(PGen):
    def __init__(self, size: int, res: int, mod: int):
        self.size = size

        if not res:
            raise ValueError('"res" cannot be zero')

        if not res % 2 and not mod % 2:
            raise ValueError('Both "res" and "mod" cannot be even')


        self.res = res
        self.mod = mod


    def _gen(self, constraints: list):
        mod = self.mod
        p   = 0

        # This ensures we only try odd numbers
        if self.mod % 2:
            if self.res % 2:
                mod *= 2
            else:
                p   += self.mod
                mod *= 2


        # Construct `p` to be the smallest integer of bitlength `size`
        # and congruent to `res` % `mod`
        p += mod*(2**(self.size-1) // mod) + mod + self.res

        while p.bit_length() == self.size:
            if is_prime(p):
                yield p

            p += mod




class ResidueConstraint(object):
    def __init__(self, res: int, mod: int):
        self.res = res
        self.mod = mod

    def __call__(self, p: int) -> bool:
        return p % self.mod == self.res


class SafePrimeConstraint(object):
    def __call__(self, p: int) -> bool:
        return is_safe_prime(p)



class SophieGermainPrimeConstraint(object):
    def __call__(self, p: int) -> bool:
        return is_sophie_germain_prime(p)


class PrimRootConstraint(object):
    def __init__(self, a: int):
        self.a = a

    def __call__(self, p: int) -> bool:
        return is_primitive_root(self.a, p)


class PGGenType(object):
    RANDOM    = RandGen
    SMOOTH    = SmoothGen
    ROCA      = ROCAGen
    CONGRUENT = CongruentGen


class PGConstraints(object):
    HAS_PRIMITIVE_ROOT = PrimRootConstraint
    HAS_RESIDUE        = ResidueConstraint
    IS_SAFE            = SafePrimeConstraint
    IS_SOPHIE_GERMAIN  = SophieGermainPrimeConstraint


class PrimeEngine(object):
    GENS        = PGGenType
    CONSTRAINTS = PGConstraints
