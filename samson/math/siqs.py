from samson.math.general import sieve_of_eratosthenes, legendre, ResidueSymbol, kth_root, tonelli, trial_division, gcd, is_prime, batch_gcd, random_int_between, mod_inv
from samson.math.polynomial import Polynomial
from samson.math.matrix import Matrix
from samson.math.symbols import Symbol
from samson.math.algebra.rings.integer_ring import ZZ
from samson.math.factors import Factors
from samson.math.sparse_vector import SparseVector
from samson.utilities.exceptions import NoSolutionException
from itertools import chain
from tqdm import tqdm
import math
from math import exp, sqrt

import logging
log = logging.getLogger(__name__)


#############
# CONSTANTS #
#############

x  = Symbol('x')
_R = ZZ/ZZ(2)
_P = ZZ[x]

_one  = _R.one
_zero = _R.zero

SIQS_TRIAL_DIVISION_EPS   = 25
SIQS_MIN_PRIME_POLYNOMIAL = 400
SIQS_MAX_PRIME_POLYNOMIAL = 4000


###########
# CLASSES #
###########

class PrimeBase(object):
    def __init__(self, p: int, n: int, t: int=None):
        self.p  = p
        self.lp = round(math.log2(p))
        self.soln1 = None
        self.soln2 = None
        self.t = t or tonelli(n % p, p)


    def __repr__(self):
        return f'<PrimeBase: {self.p}>'


    def parameterize_soln(self, b: int):
        self.soln1 = (self.t - b) % self.p
        self.soln2 = (-self.t - b) % self.p



class SMatrix(object):
    def __init__(self, rows, num_cols):
        self.rows = rows
        self.num_cols = num_cols


    @property
    def T(self):
        num_cols = len(self.rows)
        T = [SparseVector({}, zero=_R.zero) for _ in range(len(self.rows[0]))]

        for row_num, row in enumerate(self.rows):
            for col_num, val in row.values.items():
                T[col_num][row_num] = val

        for sv in T:
            sv.virtual_len = num_cols

        return SMatrix(T, num_cols=num_cols)


    def print(self):
        print([[idx for idx, val in r] for r in self.rows])



###############
# SUBROUTINES #
###############

def siqs_choose_nf_m(d):
    """
    Choose parameters nf (sieve of factor base) and m (for sieving in [-m,m].

    References:
        https://github.com/skollmann/PyFactorise/blob/master/factorise.py#L585
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

    for p in sieve_of_eratosthenes(1000000):
        if legendre(n, p) == ResidueSymbol.EXISTS:
            base.append(PrimeBase(p, n))
        
        if len(base) >= num_factors:
            return base



def gen_polys(a, b, n):
    b_orig = b
    if (2 * b > a):
        b = a - b

    g = _P([b**2 - n, 2*a*b, a**2])
    h = _P([b, a])

    return g, h


def poly_prepare_base(a, b, prime_base):
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
    return gen_polys(a, b, n)



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

    for idx, pb in enumerate(prime_base):
        if pb.p in facs and facs[pb.p] % 2:
            exp_vec[idx] = _one

    exp_vec.virtual_len = len(prime_base)
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
    """
    References:
        https://www.cs.umd.edu/~gasarch/TOPICS/factoring/fastgauss.pdf
    """
    num_rows = len(M.rows)
    num_cols = M.num_cols
    marks    = [False] * num_cols
    iterator = enumerate(M.rows)

    if visual:
        iterator = tqdm(iterator, total=num_rows, unit='row', desc='qsieve: Gaussian elimination')


    for i, row in iterator:
        for j, _elem in row:
            marks[j] = True

            for k in range(num_rows):
                if k == i:
                    continue

                if M.rows[k][j]:
                    M.rows[k] = M.rows[k].vec_add(row)
            break

    M = M.T
    solutions = []
    for i, mark in enumerate(marks):
        if not mark:
            solutions.append([M.rows[i], i])

    return solutions, marks, M


def solve_row(candidate, M, marks):
    free_row     = candidate[0]
    indices      = [idx for idx, val in free_row if val]
    solution_vec = []

    for r, mark in enumerate(marks):
        if not mark:
            continue

        for i in indices:
            if M.rows[r][i]:
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

    return gcd(abs(b-a), n)



def find_factors(n: int, solutions: list, smooth_nums: list, M: SMatrix, marks: list):
    primes     = Factors()
    left       = n
    composites = Factors()

    for K in range(len(solutions)):
        if left == 1:
            break

        sol_vec = solve_row(solutions[K], M, marks)
        factor  = solve(sol_vec, smooth_nums, n)

        # if factor not in [1, n, left] and factor not in factors:
        if factor not in primes and is_prime(factor):
            primes.add(factor)
            left //= factor

            if is_prime(left):
                primes.add(left)
                break

        elif factor not in [1, n] and factor not in composites:
            composites.add(factor)


    # Did we find anything?
    if primes or composites:
        factors = Factors() + primes

        if composites:
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



def siqs(n: int, relations_ratio: float= 1.05, visual: bool=False):
    nf, m      = siqs_choose_nf_m(len(str(n)))
    prime_base = find_base(n, nf)

    smooth_relations   = []
    num_poly = 0

    log.debug(f"Searching for smooth relations using {nf} factors over interval size {m}...")

    while True:
        required_relations = round(relations_ratio*len(prime_base))

        if visual:
            progress = tqdm(None, total=required_relations-len(smooth_relations), unit='relation', desc='qsieve: Smooth number sieve')
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
                g, h = find_next_poly(n, prime_base, num_poly, g, B, a, b)

            num_poly = (num_poly+1) % 2**(len(B)-1)
            
            # Sieve
            sieve_array = sieve(prime_base, m)
            siqs_trial_div(n, m, g, h, sieve_array, prime_base, required_relations, smooth_relations, progress_update)
        

        progress_finish()

        log.debug(f"Solving exponent parity matrix for nullspace...")
        exp_mat = SMatrix([exp_vec for _, _, exp_vec in smooth_relations], num_cols=len(prime_base)).T
        solutions, marks, M = ge_f2_nullspace(M=exp_mat, visual=visual)

        log.debug(f"Checking solutions...")
        primes, composites = find_factors(n=n, solutions=solutions, smooth_nums=smooth_relations, M=M, marks=marks)

        if primes or composites:
            return primes, composites
        else:
            relations_ratio += 0.05
