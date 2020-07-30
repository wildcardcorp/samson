from samson.math.general import sieve_of_eratosthenes, legendre, ResidueSymbol, kth_root, tonelli, trial_division, gcd
from samson.math.matrix import Matrix
from samson.math.algebra.rings.integer_ring import ZZ
from samson.utilities.exceptions import NoSolutionException
import math

import logging
log = logging.getLogger(__name__)

def find_base(n, B):
    return [2] + [p for p in sieve_of_eratosthenes(B) if legendre(n, p) == ResidueSymbol.EXISTS]


def find_smooth(factor_base, n, I, T):
    # Take the root on the low side
    root      = kth_root(n, 2)-1
    sieve_seq = [x**2 - n for x in range(root-I,root+I)]
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
        residues = [tonelli(n, p)]
        residues.append(p-residues[0])

        for res in residues:
            # Find the start of the residue of `n % p`
            start = (res-root+I) % p

            # Every pth element will have the same congruence
            for i in range(start, len(s_list), p):
                while s_list[i] and not s_list[i] % p:
                    s_list[i] //= p

            # Perform it in the negative direction
            for i in range(start+I, 0, -p):
                while s_list[i] and not s_list[i] % p:
                    s_list[i] //= p


    result = []
    F      = len(factor_base)

    for idx, val in enumerate(s_list):
        # We've met the tolerance 2^-T
        if len(result) >= F+T:
            break

        # Found a B-smooth number!
        if val in [-1, 1]:
            result.append((idx, idx+root-I, sieve_seq[idx]))
    
    return result


def build_matrix(smooth_nums, factor_base):
    factor_base_1 = [-1] + factor_base
    F   = len(factor_base_1)
    M   = []
    R   = ZZ/ZZ(2)
    zero = R(0)
    one  = R(1)

    # Build the exponent matrix
    for _, _, num in smooth_nums:
        exp_vec = [zero] * F
        n_facs  = trial_division(num, prime_base=factor_base)

        for idx, fac in enumerate(factor_base_1):
            if fac in n_facs and n_facs[fac] % 2:
                exp_vec[idx] = one

        # Found a square
        if one not in exp_vec:
            return True, num

        M.append(exp_vec)
    
    return False, Matrix(M, R).T


def ge_f2_nullspace(M: Matrix):
    """
    References:
        https://www.cs.umd.edu/~gasarch/TOPICS/factoring/fastgauss.pdf
    """
    row_len = M.num_cols
    marks   = [False] * row_len

    for i, row in enumerate(M):
        for j, elem in enumerate(row):
            if elem:
                marks[j] = True

                for k in range(row_len):
                    if k == i:
                        continue

                    if M[k, j]:
                        for l in range(row_len):
                            M[k, l] += row[l]
                break

    M = M.T
    solutions = []
    for i, mark in enumerate(marks):
        if not mark:
            solutions.append([M[i], i])

    return solutions, marks, M



def solve_row(candidate, M, marks):
    free_row     = candidate[0]
    indices      = [idx for idx, val in enumerate(free_row) if val]
    solution_vec = []

    for r, mark in enumerate(marks):
        for i in indices:
            if M[r, i] and mark:
                solution_vec.append(r)
                break

    log.debug(f"Found linear dependencies at rows {str(solution_vec)}")
    solution_vec.append(candidate[1])      
    return solution_vec



def solve(solution_vec, smooth_nums, n):
    a_square = b = 1
    for val in solution_vec:
        c = smooth_nums[val]
        a_square *= c[2]
        b        *= c[1]

    a = kth_root(a_square, 2)
    log.debug(f"Found congruence: {a}^2 = {b}^2 mod {n}")

    return gcd(b-a, n)



def find_bounds(n):
    B = pow(math.exp(math.sqrt(math.log(n)) * math.log(math.log(n))), math.sqrt(2)/4)
    return int(B), int(B**2)


def qsieve(n: int, B: int, I: int, T: int=1) -> int:
    """
    References:
        https://github.com/Maosef/Quadratic-Sieve
    """
    assert I >= B

    log.debug(f"Generating factor base...")
    # Find a factor base in which `n` has a quadratic residue
    factor_base = find_base(n, B)

    # Find smooth numbers
    log.debug(f"Searching for {len(factor_base)+T} {B}-smooth relations...")
    smooth_nums = find_smooth(factor_base, n, I, T)
    log.debug(f"Found {len(smooth_nums)} smooth relations")

    if len(smooth_nums) < len(factor_base):
        raise ValueError("Could not find enough smooth numbers. Increase sieve interval or size of factor base")

    log.debug(f"Generating exponent parity matrix...")
    is_square, t_matrix = build_matrix(smooth_nums, factor_base)

    # Free factor!
    if is_square:
        _, _, x = smooth_nums.index(t_matrix)
        factor  = gcd(smooth_nums[x][1] + kth_root(t_matrix, 2), n)
        return factor


    # Use a specialized Gaussian-Elimination to solve for the nullspace
    log.debug(f"Solving EP matrix for nullspace...")
    solutions, marks, M = ge_f2_nullspace(t_matrix)


    log.debug(f"Checking solutions...")
    for K in range(len(solutions)):
        sol_vec = solve_row(solutions[K], M, marks)
        factor  = solve(sol_vec, smooth_nums, n)

        if factor not in [1, n]:
            return factor
    
    raise NoSolutionException("No solution found in the interval")


def qsieve_auto(n: int) -> int:
    i = 0
    while True:
        i += 1
        try:
            return qsieve(n, *find_bounds(n*i))
        except (NoSolutionException, ValueError):
            continue
