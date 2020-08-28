from samson.analysis.general import count_items
from samson.math.general import is_prime, is_sophie_germain_prime, smoothness
from samson.math.factorization.general import factor
from samson.protocols.diffie_hellman import DiffieHellman

WELL_KNOWN_GROUPS = {
    DiffieHellman.MODP_768: 'MODP_768',
    DiffieHellman.MODP_1024: 'MODP_1024',
    DiffieHellman.MODP_1536: 'MODP_1536',
    DiffieHellman.MODP_2048: 'MODP_2048',
    DiffieHellman.MODP_3072: 'MODP_3072',
    DiffieHellman.MODP_4096: 'MODP_4096',
    DiffieHellman.MODP_6144: 'MODP_6144',
    DiffieHellman.MODP_8192: 'MODP_8192'
}

class IntegerAnalysis(object):
    def __init__(self, n: int, is_prime: bool, byte_aligned: bool, smoothness_ratio: float, is_safe_prime: bool, prime_name: bool, percent_one: float, is_uniform: bool, small_factors: dict):
        self.n = n
        self.is_prime = is_prime
        self.smoothness_ratio = smoothness_ratio
        self.byte_aligned = byte_aligned
        self.is_safe_prime = is_safe_prime
        self.prime_name = prime_name
        self.percent_one = percent_one
        self.is_uniform = is_uniform
        self.small_factors = small_factors


    def __repr__(self):
        return f"<IntegerAnalysis: is_prime={self.is_prime}, smoothness_ratio={self.smoothness_ratio}, byte_aligned={self.byte_aligned}, is_safe_prime={self.is_safe_prime}, prime_name='{self.prime_name}', percent_one={self.percent_one}, is_uniform={self.is_uniform}, small_factors={self.small_factors}>"

    def __str__(self):
        return self.__repr__()


    @staticmethod
    def analyze(n: int) -> 'IntegerAnalysis':
        n_is_prime   = is_prime(n)
        byte_aligned = not n % 8

        is_safe_prime = is_sophie_germain_prime(n)
        prime_name    = WELL_KNOWN_GROUPS.get(n)


        # Determine bit distribution
        bits = bin(n)[2:]
        bit_distribution = count_items(bits)
        percent_one = bit_distribution['1'] / len(bits)

        uniform_dist     = abs(0.50 - percent_one) < 0.05
        factor_mod       = n - (1 if n_is_prime else 0)
        small_factors    = factor(factor_mod, use_rho=False, use_siqs=False, use_smooth_p=False)
        smoothness_ratio = smoothness(factor_mod, factors=small_factors)

        return IntegerAnalysis(n=n, is_prime=n_is_prime, smoothness_ratio=smoothness_ratio, byte_aligned=byte_aligned, is_safe_prime=is_safe_prime, prime_name=prime_name, percent_one=percent_one, is_uniform=uniform_dist, small_factors=small_factors)
