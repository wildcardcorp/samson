from samson.math.general import sieve_of_eratosthenes, legendre, ResidueSymbol, kth_root, tonelli, trial_division, gcd
from samson.math.matrix import Matrix
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

_R = ZZ/ZZ(2)

def find_base(n, B):
    return [2] + [p for p in sieve_of_eratosthenes(B) if legendre(n, p) == ResidueSymbol.EXISTS]


def find_smooth(factor_base: list, n: int, T: int, chunk: int=0, visual: bool=False):
    # Take the root on the low side
    root       = kth_root(n, 2)-1
    result     = []
    F          = len(factor_base)
    chunk_size = 2048
    residues   = {p: tonelli(n, p) for p in factor_base[1:]}
    residues   = {p: (r, p-r) for p,r in residues.items()}

    if visual:
        progress = tqdm(None, total=F+T, unit='relation', desc='qsieve: Smooth number sieve')
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


    while True:
        chunk    += 1
        I         = chunk*chunk_size
        sieve_seq = [x**2 - n for x in chain(range(root-I, root-I+chunk_size), range(root+I-chunk_size, root+I))]
        s_list    = sieve_seq.copy()

        # Remove all factors of 2 (can't tonelli over 2)
        if 2 in factor_base:
            i = 0
            while s_list[i] % 2:
                i += 1

            for j in range(i, len(s_list), 2):
                while s_list[j] and not s_list[j] % 2:
                    s_list[j] //= 2


        for p in factor_base[1:]:
            for res in residues[p]:
                # Find the start of the residue of `n % p`
                start = (res-root+I) % p

                # Every pth element will have the same congruence
                for i in range(start, len(s_list), p):
                    while s_list[i] and not s_list[i] % p:
                        s_list[i] //= p


                # Perform it in the negative direction
                end  = start+I
                end -= math.ceil((end+1 - len(s_list)) / p) * p

                for i in range(end, 0, -p):
                    while s_list[i] and not s_list[i] % p:
                        s_list[i] //= p


        for idx, val in enumerate(s_list):
            # We've met the tolerance 2^-T
            if len(result) >= F+T:
                progress_finish()
                return result, chunk

            # Found a B-smooth number!
            if val in [-1, 1]:
                result.append((idx+root-I, sieve_seq[idx]))
                progress_update(1)



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


def build_matrix(smooth_nums, factor_base):
    factor_base_1 = [-1] + factor_base
    F    = len(factor_base_1)
    M    = []
    zero = _R.zero
    one  = _R.one

    # Build the exponent matrix
    for _, num in smooth_nums:
        exp_vec = SparseVector({}, zero=zero)
        n_facs  = trial_division(num, prime_base=factor_base)

        for idx, fac in enumerate(factor_base_1):
            if fac in n_facs and n_facs[fac] % 2:
                exp_vec[idx] = one

        # Found a square
        if not exp_vec:
            return True, num

        exp_vec.virtual_len = F
        M.append(exp_vec)

    return False, SMatrix(M, num_cols=F).T



def ge_f2_nullspace(M: Matrix, visual: bool=False):
    """
    References:
        https://www.cs.umd.edu/~gasarch/TOPICS/factoring/fastgauss.pdf
    """
    num_rows = len(M.rows)
    num_cols = M.num_cols
    marks    = [False] * num_cols

    #MT = M.T
    iterator = enumerate(M.rows)

    if visual:
        iterator = tqdm(iterator, total=num_rows, unit='row', desc='qsieve: Gaussian elimination')


    for i, row in iterator:
        for j, _elem in row:
            marks[j] = True
            #row_j    = list(MT.rows[j])

            # for k, _val in row_j:
            #     if k == i:
            #         continue

            #     for l in range(num_cols):
            #         r = row[l]
            #         M.rows[k][l]  += r
            #         MT.rows[l][k] += r

            # break

            for k in range(num_rows):
                if k == i:
                    continue

                if M.rows[k][j]:
                    for l in range(num_cols):
                        M.rows[k][l] += row[l]
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

    return gcd(b-a, n)



def find_bounds(n):
    B = pow(exp(sqrt(math.log(n)*math.log(math.log(n)))), sqrt(2)/3)
    return int(B)


def qsieve(n: int, B: int=0, T: int=1, visual: bool=False) -> int:
    """
    References:
        https://github.com/Maosef/Quadratic-Sieve
    """
    if not B:
        B = find_bounds(n)

    log.debug(f"Generating factor base...")

    # Find a factor base in which `n` has a quadratic residue
    factor_base = find_base(n, B)

    # Find smooth numbers
    chunk = 0
    smooth_nums = []
    attempt = 0
    while True:
        log.debug(f"Searching for {len(factor_base)+T} {B}-smooth relations...")
        found_smooth, chunk = find_smooth(factor_base, n, T=T, chunk=chunk, visual=visual)
        log.debug(f"Found {len(found_smooth)} new smooth relations")

        smooth_nums.extend(found_smooth)

        log.debug(f"Generating exponent parity matrix...")
        is_square, t_matrix = build_matrix(smooth_nums, factor_base)

        # Free factor!
        if is_square:
            _, x = smooth_nums.index(t_matrix)
            factor  = gcd(smooth_nums[x][1] + kth_root(t_matrix, 2), n)
            return factor


        # Use a specialized Gaussian-Elimination to solve for the nullspace
        log.debug(f"Solving EP matrix for nullspace...")
        solutions, marks, M = ge_f2_nullspace(t_matrix, visual)


        log.debug(f"Checking solutions...")
        for K in range(len(solutions)):
            sol_vec = solve_row(solutions[K], M, marks)
            factor  = solve(sol_vec, smooth_nums, n)

            if factor not in [1, n]:
                return factor
    

        # If we're here, we didn't find anything
        # Restart the process but build on our old smooth numbers
        attempt += 1
        T = len(factor_base) - (10 * attempt)

    raise NoSolutionException("No solution found in the interval")


# def qsieve_auto(n: int, visual: bool=False) -> int:
#     return qsieve(n, find_bounds(n), visual=visual)

#     # i = 0
#     # while True:
#     #     i += 1
#     #     try:
#     #         return qsieve(n, find_bounds(n*i), visual=visual)
#     #     except NoSolutionException:
#     #         continue
