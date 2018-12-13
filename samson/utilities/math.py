from copy import deepcopy
from samson.utilities.general import rand_bytes
from sympy.matrices import Matrix, GramSchmidt
from sympy import isprime, Poly
from sympy.abc import x
import math

def gcd(a: int, b: int) -> int:
    """
    Recursively computes the greatest common denominator.

    Parameters:
        a (int): First integer.
        b (int): Second integer.
    
    Returns:
        int: GCD of `a` and `b`.
    """
    while True:
        if b == 0:
            return a
        else:
            a, b = b, a % b


# https://anh.cs.luc.edu/331/notes/xgcd.pdf
def xgcd(a: int, b: int) -> (int, int, int):
    """
    Extended Euclidean algorithm form of GCD.
    `ax + by = gcd(a, b)`

    Parameters:
        a (int): First integer.
        b (int): Second integer.
    
    Returns:
        (int, int, int): Formatted as (GCD, x, y).
    """
    prevx, x = 1, 0; prevy, y = 0, 1
    while b:
        q = a//b
        x, prevx = prevx - q*x, x
        y, prevy = prevy - q*y, y
        a, b = b, a % b
    return a, prevx, prevy



def lcm(a: int, b: int) -> int:
    """
    Calculates the least common multiple of `a` and `b`.

    Parameters:
        a (int): First integer.
        b (int): Second integer.
    
    Returns:
        int: Least common multiple.
    """
    return a // gcd(a, b) * b



def mod_inv(a: int, n: int) -> int:
    """
    Calculates the modular inverse according to
    https://en.wikipedia.org/wiki/Euclidean_algorithm#Linear_Diophantine_equations
    and https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm.

    Parameters:
        a (int): Integer.
        n (int): Modulus.
    
    Returns:
        int: Modular inverse of `a` over `n`.
    """

    _, x, _ = xgcd(a, n)

    if (a * x) % n != 1:
        raise Exception("'a' is not invertible")

    if x < 0:
        x = x + n

    return x


def modexp (g: int, u: int, p: int) -> int:
    """
    Computes `s = (g ^ u) mod p` (see Bruce Schneier's book, _Applied Cryptography_ p. 244).

    Parameters:
        g (int): Base.
        u (int): Exponent.
        p (int): Modulus.
    
    Returns:
        int: Modular exponentiation.
    """
    s = 1
    while u != 0:
        if u & 1:
            s = (s * g)%p
        u >>= 1
        g = (g * g)%p
    return s


# https://stackoverflow.com/questions/23621833/is-cube-root-integer
def kth_root(n: int, k: int) -> int:
    """
    Calculates the `k`-th integer root of `n`.

    Parameters:
        n (int): Integer.
        k (int): Root (e.g. 2).
    
    Returns:
        int: `k`-th integer root of `n
    """
    lb,ub = 0,n #lower bound, upper bound
    while lb < ub:
        guess = (lb+ub)//2
        if pow(guess,k) < n: lb = guess+1
        else: ub = guess
    return lb


def crt(residues: list, moduli: list) -> (int, int):
    """
    Performs the Chinese Remainder Theorem and returns the computed `x` and modulus.

    Parameters:
        residues (list): Residues of `x` in order relative to `moduli`.
        moduli   (list): Moduli of the residues.
    
    Returns:
        (int, int): Formatted as (computed `x`, modulus).
    """
    assert len(residues) == len(moduli)
    x = residues[0]
    Nx = moduli[0]

    for i in range(1, len(residues)):
        x = (mod_inv(Nx, moduli[i]) * (residues[i] - x)) * Nx + x
        Nx = Nx * moduli[i]

    return x % Nx, Nx



def legendre(a: int, p: int) -> int:
    """
    Calculates the Legendre symbol of `a` mod `p`. Nonzero quadratic residues mod `p` return 1 and nonzero, non-quadratic residues return -1. Zero returns 0.

    Parameters:
        a (int): Integer.
        p (int): Modulus.
    
    Returns:
        int: Legendre symbol.
    """
    return pow(a, (p - 1) // 2, p)


# https://crypto.stackexchange.com/questions/22919/explanation-of-each-of-the-parameters-used-in-ecc
# https://www.geeksforgeeks.org/find-square-root-modulo-p-set-2-shanks-tonelli-algorithm/
# https://rosettacode.org/wiki/Tonelli-Shanks_algorithm#Python


def tonelli(n: int, p: int) -> int:
    """
    Performs the Tonelli-Shanks algorithm for calculating the square root of `n` mod `p`.

    Parameters:
        n (int): Integer.
        p (int): Modulus.
    
    Returns:
        int: Square root of `n` mod `p`.
    """
    assert legendre(n, p) == 1, "not a square (mod p)"
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    if s == 1:
        return pow(n, (p + 1) // 4, p)
    for z in range(2, p):
        if p - 1 == legendre(z, p):
            break
    c = pow(z, q, p)
    r = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    m = s
    t2 = 0
    while (t - 1) % p != 0:
        t2 = (t * t) % p
        for i in range(1, m):
            if (t2 - 1) % p == 0:
                break
            t2 = (t2 * t2) % p
        b = pow(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i
    return r



# https://github.com/orisano/olll/blob/master/olll.py
# https://en.wikipedia.org/wiki/Lenstra%E2%80%93Lenstra%E2%80%93Lov%C3%A1sz_lattice_basis_reduction_algorithm
def lll(in_basis: list, delta=0.75) -> Matrix:
    """
    Performs the Lenstra–Lenstra–Lovász lattice basis reduction algorithm.

    Parameters:
        in_basis (list): List of Matrix objects representing the original basis.
        delta   (float): Minimum optimality of the reduced basis.
    
    Returns:
        Matrix: Reduced basis.
    """
    basis = deepcopy(in_basis)
    n = len(basis)
    ortho = GramSchmidt(basis)

    def mu(i, j):
        return ortho[j].dot(basis[i]) / ortho[j].dot(ortho[j])

    k = 1
    while k < n:
        for j in range(k - 1, -1, -1):
            mu_kj = mu(k, j)
            if abs(mu_kj) > 0.5:
                basis[k] = basis[k] - basis[j] * round(mu_kj)
                ortho = GramSchmidt(basis)


        if ortho[k].dot(ortho[k]) >= (delta - mu(k, k - 1)**2) * (ortho[k - 1].dot(ortho[k - 1])):
            k += 1
        else:
            basis[k], basis[k - 1] = deepcopy(basis[k - 1]), deepcopy(basis[k])
            ortho = GramSchmidt(basis)
            k = max(k - 1, 1)

    return Matrix([list(map(int, b)) for b in basis])



def generate_superincreasing_seq(length: int, max_diff: int, starting: int=0) -> list:
    """
    Generates a superincreasing sequence.

    Parameters:
        length   (int): Number of elements to generate.
        max_diff (int): Maximum difference between the sum of all elements before and the next element.
        starting (int): Minimum starting integer.
    
    Returns:
        list: List of the superincreasing sequence.
    """
    seq = []

    last_sum = starting
    for _ in range(length):
        delta = int.from_bytes(rand_bytes(math.ceil(math.log(max_diff, 256))), 'big') % max_diff
        seq.append(last_sum + delta)
        last_sum = sum(seq)

    return seq



def find_coprime(p: int, search_range: list) -> int:
    """
    Attempts to find an integer coprime to `p`.

    Parameters:
        p             (int): Integer to find coprime for.
        search_range (list): Range to look in.
    
    Returns:
        int: Integer coprime to `p`.
    """
    for i in search_range:
        if gcd(p, i) == 1:
            return i



def find_prime(bits: int) -> int:
    """
    Finds a prime of `bits` bits.

    Parameters:
        bits (int): Bit length of prime.
    
    Returns:
        int: Prime.
    """
    rand_num = int.from_bytes(rand_bytes(math.ceil(bits / 8)), 'big')
    rand_num |= 2**(bits - 1)
    return next_prime(rand_num)



def next_prime(start_int: int) -> int:
    """
    Finds the next prime.

    Parameters:
        start_int (int): Integer to start search at.
    
    Returns:
        int: Prime.
    """
    start_int |= 1
    while not isprime(start_int):
        start_int += 2

    return start_int



# https://en.wikipedia.org/wiki/Berlekamp%E2%80%93Massey_algorithm
def berlekamp_massey(output_list: list) -> Poly:
    """
    Performs the Berlekamp-Massey algorithm to find the shortest LFSR for a binary output sequence.

    Parameters:
        output_list (list): Output of LFSR.
    
    Returns:
        Poly: Polyomial that represents the shortest LFSR.
    """
    n = len(output_list)
    b = [1] + [0] * (n - 1)
    c = [1] + [0] * (n - 1)

    L = 0
    m = -1

    i  = 0
    while i < n:
        out_vec = output_list[i - L:i][::-1]
        c_vec = c[1:L+i]
        d = output_list[i] + sum([s_x * c_x for s_x, c_x in zip(out_vec, c_vec)]) % 2

        if d == 1:
            t = deepcopy(c)
            p = [0] * n
            for j in range(L):
                if b[j] == 1:
                    p[j + i - m] = 1

            c = [(c_x + p_x) % 2 for c_x, p_x in zip(c, p)]

            if L <= i / 2:
                L = i + 1 - L
                m = i
                b = t

        i += 1

    return Poly(c[:L + 1], x)


def is_power_of_two(n: int) -> bool:
    """
    Determines if `n` is a power of two.

    Parameters:
        n (int): Integer.
    
    Returns:
        bool: Whether or not `n` is a power of two.
    """
    return n != 0 and (n & (n - 1) == 0)
