from samson.math.general import sieve_of_eratosthenes, legendre, ResidueSymbol, kth_root, tonelli, gcd, is_prime, batch_gcd, random_int_between, mod_inv
from samson.math.polynomial import Polynomial
from samson.math.matrix import Matrix
from samson.math.symbols import Symbol
from samson.math.algebra.rings.integer_ring import ZZ
from samson.math.factorization.factors import Factors
from samson.math.factorization.general import trial_division
from samson.math.sparse_vector import SparseVector
from tqdm import tqdm
import math


import logging
log = logging.getLogger(__name__)


# """
# References:
#     "Factoring Integers with the Self-Initializing Quadratic Sieve" (https://pdfs.semanticscholar.org/5c52/8a975c1405bd35c65993abf5a4edb667c1db.pdf)
#     "A fast algorithm for gaussian elimination over GF(2) and its implementation on the GAPP" (https://www.cs.umd.edu/~gasarch/TOPICS/factoring/fastgauss.pdf)
#     https://github.com/skollmann/PyFactorise/blob/master/factorise.py
# """

#############
# CONSTANTS #
#############

_x  = Symbol('x')
_R = ZZ/ZZ(2)
_P = ZZ[_x]

_one  = _R.one
_zero = _R.zero

SIQS_TRIAL_DIVISION_EPS   = 25
SIQS_MIN_PRIME_POLYNOMIAL = 400
SIQS_MAX_PRIME_POLYNOMIAL = 4000


###########
# CLASSES #
###########

class PrimeBase(object):
    def __init__(self, p: int, n: int, t: int=None, lp: int=None):
        self.p  = p
        self.lp = lp or round(math.log2(p))
        self.soln1 = None
        self.soln2 = None
        self.t = t or tonelli(n % p, p)


    def __repr__(self):
        return f'<PrimeBase: {self.p}>'




class BMatrix(object):
    def __init__(self, rows, num_cols):
        self.rows = rows
        self.num_cols = num_cols


    @property
    def T(self):
        T = [[b for b in bin(row)[2:].zfill(self.num_cols)[::-1]] for row in self.rows]
        return BMatrix([int(''.join([T[r][c] for r in range(len(self.rows))][::-1]), 2) for c in range(self.num_cols)], num_cols=len(self.rows))


    def add_pivot(self, idx, row):
        self.rows[idx] ^= row


    def find_pivot(self, idx):
        row = self.rows[idx]
        return lowest_set_bit(row) if row else None


    def print(self):
        print([[c for c in range(self.num_cols) if self[r, c]] for r in range(len(self.rows))])


    def __getitem__(self, idx):
        i, j = idx
        return self.rows[i] >> j & 1




###############
# SUBROUTINES #
###############

def siqs_choose_nf_m(d):
    """
    Choose parameters nf (sieve of factor base) and m (for sieving in [-m,m].
    """
    # Using similar parameters as msieve-1.52
    if d <= 34:
        return 200, 65536
    if d <= 36:
        return 300, 65536
    if d <= 38:
        return 400, 65536
    if d <= 40:
        return 500, 65536
    if d <= 42:
        return 600, 65536
    if d <= 44:
        return 700, 65536
    if d <= 48:
        return 1000, 65536
    if d <= 52:
        return 1200, 65536
    if d <= 56:
        return 2000, 65536 * 3
    if d <= 60:
        return 4000, 65536 * 3
    if d <= 66:
        return 6000, 65536 * 3
    if d <= 74:
        return 10000, 65536 * 3
    if d <= 80:
        return 30000, 65536 * 3
    if d <= 88:
        return 50000, 65536 * 3
    if d <= 94:
        return 60000, 65536 * 9
    return 100000, 65536 * 9



def find_base(n, num_factors):
    base = [PrimeBase(2, n, t=1)]

    for p in sieve_of_eratosthenes(2**64):
        if legendre(n, p) == ResidueSymbol.EXISTS:
            base.append(PrimeBase(p, n))

        if len(base) >= num_factors:
            return base



def gen_polys(a, b, n):
    if (2 * b > a):
        b = a - b

    g = _P([b**2 - n, 2*a*b, a**2])
    h = _P([b, a])

    return g, h


def poly_prepare_base(a, b, prime_base):
    if (2 * b > a):
        b = a - b

    for pb in prime_base:
        if a % pb.p:
            pb.ainv  = mod_inv(a, pb.p)
            pb.soln1 = (pb.ainv * (pb.t - b)) % pb.p
            pb.soln2 = (pb.ainv * (-pb.t - b)) % pb.p



def find_first_poly(n, m, prime_base):
    # TODO: Binary search?
    p_min_i = None
    p_max_i = None

    for i, pb in enumerate(prime_base):
        if p_min_i is None and pb.p >= SIQS_MIN_PRIME_POLYNOMIAL:
            p_min_i = i

        if p_max_i is None and pb.p > SIQS_MAX_PRIME_POLYNOMIAL:
            p_max_i = i - 1
            break


    # The following may happen if the factor base is small, make sure
    # that we have enough primes.
    if p_max_i is None:
        p_max_i = len(prime_base) - 1

    if p_min_i is None or p_max_i - p_min_i < 20:
        p_min_i = min(p_min_i, 5)


    # TODO: Make pretty
    target  = math.ceil(kth_root(2*n, 2) / m)
    target1 = math.ceil(target / ((prime_base[p_min_i].p + prime_base[p_max_i].p) / 2)**0.5)

    best_q, best_a, best_ratio = None, None, None

    for _ in range(30):
        a = 1
        q = []

        while a < target1:
            p_i = 0

            while not p_i or p_i in q:
                p_i = random_int_between(p_min_i, p_max_i)

            p  = prime_base[p_i].p
            a *= p
            q.append(p_i)

        ratio = a / target

        # Ideally, 'best_ratio' converges on 0.9
        if not best_ratio or (ratio >= 0.9 and ratio < best_ratio) or best_ratio < 0.9 and ratio > best_ratio:
            best_q     = q
            best_a     = a
            best_ratio = ratio


        B = []
        a = best_a
        for l in best_q:
            pb_l = prime_base[l]
            p_l  = pb_l.p

            assert a % p_l == 0

            gamma = (pb_l.t * mod_inv(a // p_l, p_l)) % p_l
            if gamma > p_l // 2:
                gamma = p_l - gamma

            B.append(a // p_l * gamma)


        b = sum(B) % a
        poly_prepare_base(a, b, prime_base)

        return gen_polys(a, b, n), B, a, b



def lowest_set_bit(a):
    b = (a & -a)
    low_bit = -1
    while (b):
        b >>= 1
        low_bit += 1
    return low_bit



def find_next_poly(n, prime_base, i, g, B, a, b):
    v = lowest_set_bit(i)
    z = -1 if math.ceil(i / (2**v)) % 2 else 1
    b = (b + 2*z*B[v-1]) % a

    poly_prepare_base(a, b, prime_base)
    return gen_polys(a, b, n), a, b


def sieve(prime_base, m):
    sieve_array = [0]*(2*m+1)

    for pb in prime_base:
        if pb.soln1 is None or pb.p < 21:
            continue

        p  = pb.p
        lp = pb.lp

        # Do the "bit sieve" heuristic
        for soln in [pb.soln1, pb.soln2]:
            i_start = -((m + soln) // p)
            a_start = soln + i_start * p

            for a in range(a_start+m, 2*m+1, p):
                sieve_array[a] += lp

    return sieve_array



def create_exp_vec(facs: Factors, prime_base: list):
    exp_vec = SparseVector({}, zero=_zero)

    for idx, pb in enumerate([PrimeBase(-1, n=0, t=1, lp=1)] + prime_base):
        if pb.p in facs and facs[pb.p] % 2:
            exp_vec[idx] = _one

    exp_vec.virtual_len = len(prime_base)+1
    return exp_vec



def siqs_trial_div(n: int, m: int, g: Polynomial, h: Polynomial, sieve_array: list, prime_base: list, required_relations: int, smooth_relations: list, progress_update):
    smooth_threshold = math.log2(m * kth_root(n, 2)) - SIQS_TRIAL_DIVISION_EPS

    for i, bit_smooth in enumerate(sieve_array):
        if bit_smooth >= smooth_threshold:
            x  = i - m
            gx = int(g(x))

            facs = trial_division(gx, prime_base=[pb.p for pb in prime_base])

            # Is it smooth over the prime_base?
            if facs.recombine() == gx:
                u = int(h(x))
                smooth_relations.append((u, gx, create_exp_vec(facs, prime_base)))
                progress_update(1)

                if len(smooth_relations) >= required_relations:
                    return



def ge_f2_nullspace(M: Matrix, visual: bool=False):
    num_rows = len(M.rows)
    num_cols = M.num_cols
    marks    = [False] * num_cols
    iterator = enumerate(M.rows)

    if visual:
        iterator = tqdm(iterator, total=num_rows, unit='row', desc='siqs: Gaussian elimination')

    for i, row in iterator:
        j = M.find_pivot(i)
        if j is None:
            continue

        marks[j] = True

        for k in range(num_rows):
            if k == i:
                continue

            if M[k, j]:
                M.add_pivot(k, row)

    M = M.T
    solutions = []
    for i, mark in enumerate(marks):
        if not mark:
            solutions.append([M.rows[i], i])

    return solutions, marks, M



def solve_row(candidate, M, marks):
    free_row     = candidate[0]
    indices      = [idx for idx, val in enumerate(bin(free_row)[2:].zfill(M.num_cols)[::-1]) if val == '1']
    solution_vec = []


    for r, mark in enumerate(marks):
        if not mark:
            continue

        for i in indices:
            if M[r, i]:
                solution_vec.append(r)
                break

    log.debug(f"Found linear dependencies at rows {str(solution_vec)}")
    solution_vec.append(candidate[1])
    return solution_vec



def solve(solution_vec, smooth_nums, n):
    a_square = b = 1
    for val in solution_vec:
        c = smooth_nums[val]
        a_square *= c[1]
        b        *= c[0]

    a = kth_root(a_square, 2)
    log.debug(f"Found congruence: {a}^2 = {b}^2 mod {n}")

    return gcd(abs(b-a), n), gcd(abs(b+a), n)



def find_factors(n: int, solutions: list, smooth_nums: list, M: BMatrix, marks: list):
    primes     = Factors()
    left       = n
    composites = Factors()

    for solution in solutions:
        if left == 1:
            break

        sol_vec = solve_row(solution, M, marks)
        factors = solve(sol_vec, smooth_nums, n)

        for factor in factors:
            fac_prime = is_prime(factor)
            if factor not in primes and fac_prime:
                primes.add(factor)
                left //= factor

                if is_prime(left):
                    primes.add(left)
                    left //= factor
                    break

            elif not fac_prime and factor not in [1, n] and factor not in composites:
                composites.add(factor)


    # Did we find anything?
    if primes or composites:
        factors = Factors() + primes

        if left > 1 and composites:
            # Use batch_gcd over composites
            for fac in batch_gcd(composites):
                if is_prime(fac) and fac not in factors:
                    factors.add(fac)

                elif fac != 1 and fac not in composites:
                    composites.add(fac)


            # See if we can use our primes to pull apart the composites
            for com in composites:
                com_facs  = trial_division(com, prime_base=primes)
                candidate = com // com_facs.recombine()

                if is_prime(candidate) and candidate not in factors:
                    factors.add(candidate)

                elif candidate != 1 and candidate not in composites:
                    composites.add(fac)

        primes = factors

    return primes, composites


def siqs(n: int, bound_ratio: float=1.0, relations_ratio: float=1.05, visual: bool=False):
    nf, m      = siqs_choose_nf_m(len(str(n)))
    nf         = int(nf * bound_ratio)
    prime_base = find_base(n, nf)

    smooth_relations = []
    num_poly = 0

    log.debug(f"Searching for smooth relations using {nf} factors over interval size {m}...")

    while True:
        required_relations = round(relations_ratio*len(prime_base))

        if visual:
            progress = tqdm(None, total=required_relations-len(smooth_relations), unit='relation', desc='siqs: Smooth number sieve')
            def progress_update(x):
                progress.update(x)
                progress.refresh()

            def progress_finish():
                progress.close()

        else:
            def progress_update(x):
                pass

            def progress_finish():
                pass


        while len(smooth_relations) < required_relations:
            if not num_poly:
                (g, h), B, a, b = find_first_poly(n, m, prime_base)
            else:
                (g, h), a, b = find_next_poly(n, prime_base, num_poly, g, B, a, b)

            num_poly = (num_poly+1) % 2**(len(B)-1)

            # Sieve
            sieve_array = sieve(prime_base, m)
            siqs_trial_div(n, m, g, h, sieve_array, prime_base, required_relations, smooth_relations, progress_update)



        progress_finish()

        log.debug("Solving exponent parity matrix for nullspace...")

        # 'num_cols' is len(prime_base)+1 because we want Gaussian elimination to cancel out negatives
        exp_vecs = [exp_vec for _, _, exp_vec in smooth_relations]
        exp_ints = [int(''.join([str(int(exp_vec[b])) for b in range(len(exp_vec))])[::-1], 2) for exp_vec in exp_vecs]
        bexp_mat = BMatrix(exp_ints, num_cols=len(prime_base)+1).T

        solutions, marks, M = ge_f2_nullspace(M=bexp_mat, visual=visual)
        primes, composites  = find_factors(n=n, solutions=solutions, smooth_nums=smooth_relations, M=M, marks=marks)


        if primes or composites:
            return primes, composites
        else:
            relations_ratio += 0.05
