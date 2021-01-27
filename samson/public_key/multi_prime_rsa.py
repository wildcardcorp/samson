from samson.math.general import crt, product, gcd, find_prime, lcm, mod_inv
from samson.core.base_object import BaseObject

class MultiPrimeRSA(BaseObject):
    def __init__(self, ps: list, ds: list, es: list, d: int, e: int):
        self.ps = ps
        self.ds = ds
        self.es = es
        self.d  = d
        self.e  = e


    def encrypt(self, pt: int) -> int:
        return crt([(pow(pt, e, p), p) for e, p in zip(self.es, self.ps)])[0]


    def decrypt(self, ct: int) -> int:
        return crt([(pow(ct, d, p), p) for d, p in zip(self.ds, self.ps)])[0]

    @property
    def n(self) -> int:
        return product(self.ps)


    @staticmethod
    def from_specs(prime_size: int=None, minumum_modulus_bits: int=None, e: int=None, d: int=None, primes: list=None) -> 'MultiPrimeRSA':
        if not primes:
            num_prime = (minumum_modulus_bits + prime_size-1) // prime_size
            phi = e

            while gcd(e, phi) != 1 or len(set(primes)) < len(primes):
                primes = [find_prime(prime_size) for _ in range(num_prime)]
                phi    = lcm(*[p-1 for p in primes])


        phi = product([p-1 for p in primes])
        if e:
            d  = mod_inv(e, phi)
        else:
            e  = mod_inv(d, phi)

        ds = [d % (p-1) for p in primes]
        es = [e % (p-1) for p in primes]

        return MultiPrimeRSA(primes, ds, es, d, e)
