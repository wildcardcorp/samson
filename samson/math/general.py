from samson.utilities.general import rand_bytes, add_or_increment
from samson.utilities.exceptions import NotInvertibleException, ProbabilisticFailureException, SearchspaceExhaustedException
from sympy.matrices import Matrix, GramSchmidt
from sympy import sieve
from itertools import chain
from types import FunctionType
from copy import deepcopy
from enum import Enum
import math

def int_to_poly(integer: int, modulus: int=2) -> object:
    """
    Encodes an integer as a polynomial.

    Parameters:
        integer (int): Integer to encode.
        modulus (int): Modulus to reduce the integer over.
    
    Returns:
        object: Polynomial representation.
    
    Examples:
        >>> from samson.math.general import int_to_poly
        >>> int_to_poly(100)
        <Polynomial: x**6 + x**5 + x**2, coeff_ring=ZZ/ZZ(2)>

        >>> int_to_poly(128, 3)
        <Polynomial: x**4 + x**3 + ZZ(2)*x**2 + ZZ(2), coeff_ring=ZZ/ZZ(3)>

    """
    from samson.math.all import ZZ, Polynomial
    base_coeffs = []

    # Use != to handle negative numbers
    while integer != 0 and integer != -1:
        integer, r = divmod(integer, modulus)
        base_coeffs.append(r)

    return Polynomial(base_coeffs, ZZ/ZZ(modulus))


def poly_to_int(poly: object) -> int:
    """
    Encodes an polynomial as a integer.

    Parameters:
        poly (Polynomial): Polynomial to encode.
        modulus     (int): Modulus to reconstruct the integer with.
    
    Returns:
        int: Integer representation.
    
    Examples:
        >>> from samson.math.general import int_to_poly, poly_to_int
        >>> poly_to_int(int_to_poly(100))
        100

        >>> poly_to_int(int_to_poly(100, 3))
        100

    """
    modulus = poly.coeff_ring.order
    value   = 0
    for idx, coeff in poly.coeffs:
        value += int(coeff) * modulus**idx

    return value


def frobenius_monomial_base(poly: object) -> list:
    """
    Generates a list of monomials of x**(i*p) % g for range(poly.degrees()). Used with Frobenius map.

    Adapted from https://github.com/sympy/sympy/blob/d1301c58be7ee4cd12fd28f1c5cd0b26322ed277/sympy/polys/galoistools.py

    Parameters:
        poly (Polynomial): Polynomial to generate bases for.

    Returns:
        list: List of monomial bases mod g.
    """
    from samson.math.symbols import oo

    n = poly.degree()
    if n == 0:
        return []

    P = poly.ring
    q = poly.coeff_ring.order if poly.coeff_ring.order != oo else poly.coeff_ring.characteristic
    bases = [None]*n
    bases[0] = P.one()

    if q < n:
        for i in range(1, n):
            bases[i] = (bases[i-1] << q) % poly

    elif n > 1:
        R = P/poly
        x = P.symbol
        bases[1] = R(x)**q

        for i in range(2, n):
            bases[i] = bases[i-1] * bases[1]

        # Peel off the quotient ring
        for i in range(1, n):
            bases[i] = bases[i].val

    return bases


def frobenius_map(f: object, g: object, bases: list=None) -> object:
    """
    Computes f**p % g using the Frobenius map.

    https://en.wikipedia.org/wiki/Finite_field#Frobenius_automorphism_and_Galois_theory

    Parameters:
        f (Polynomial): Base.
        g (Polynomial): Modulus.
        bases   (list): Frobenius monomial bases. Will generate if not provided.
    
    Returns:
        Polynomial: f**p % g
    """
    if not bases:
        bases = frobenius_monomial_base(g)

    dg = g.degree()
    df = f.degree()
    P  = f.ring

    if df >= dg:
        f %= g
        df = f.degree()

    if not f:
        return f

    sf = P([f.coeffs[0]])

    for i in range(1, df+1):
        sf += bases[i] * P([f.coeffs[i]])

    return sf



def gcd(a: int, b: int) -> int:
    """
    Recursively computes the greatest common denominator.

    Parameters:
        a (int): First integer.
        b (int): Second integer.
    
    Returns:
        int: GCD of `a` and `b`.
    
    Examples:
        >>> from samson.math.general import gcd
        >>> gcd(256, 640)
        128

        >>> from samson.math.algebra.all import FF
        >>> from samson.math.symbols import Symbol
        >>> x = Symbol('x')
        >>> P = FF(2, 8)[x]
        >>> gcd(P(x**2), P(x**5))
        <Polynomial: x**2, coeff_ring=F_(2**8)>

    """
    while True:
        if not b:
            return a
        else:
            a, b = b, a % b


def xgcd(a: int, b: int) -> (int, int, int):
    """
    Extended Euclidean algorithm form of GCD.
    `ax + by = gcd(a, b)`

    https://anh.cs.luc.edu/331/notes/xgcd.pdf

    Parameters:
        a (int): First integer.
        b (int): Second integer.
    
    Returns:
        (int, int, int): Formatted as (GCD, x, y).
    
    Examples:
        >>> from samson.math.general import xgcd
        >>> xgcd(10, 5)
        (5, 0, 1)

        >>> from samson.math.algebra.all import FF
        >>> from samson.math.symbols import Symbol
        >>> x = Symbol('x')
        >>> P = FF(2, 8)[x]
        >>> xgcd(P(x**2), P(x**5))
        (<Polynomial: x**2, coeff_ring=F_(2**8)>, <Polynomial: F_(2**8)(ZZ(1)), coeff_ring=F_(2**8)>, <Polynomial: F_(2**8)(ZZ(0)), coeff_ring=F_(2**8)>)

    """
    from samson.math.algebra.rings.integer_ring import ZZ

    # For convenience
    peel_ring = False
    if type(a) is int:
        peel_ring = True
        a = ZZ(a)
        b = ZZ(b)

    R = a.ring

    # Generic xgcd
    prevx, x = R.one(), R.zero(); prevy, y = R.zero(), R.one()
    while b:
        q = a // b
        x, prevx = prevx - q*x, x
        y, prevy = prevy - q*y, y
        a, b = b, a % b

    g, s, t = a, prevx, prevy

    # Normalize if possible
    if g.is_invertible() and s:
        s_g = s // g
        if s_g:
            g, s, t = g // g, s_g, t // g


    if peel_ring:
        g = g.val
        s = s.val
        t = t.val

    return g, s, t


def lcm(a: int, b: int) -> int:
    """
    Calculates the least common multiple of `a` and `b`.

    Parameters:
        a (int): First integer.
        b (int): Second integer.
    
    Returns:
        int: Least common multiple.
    
    Examples:
        >>> from samson.math.general import lcm
        >>> lcm(2, 5)
        10

        >>> from samson.math.algebra.all import FF
        >>> from samson.math.symbols import Symbol
        >>> x = Symbol('x')
        >>> P = FF(2, 8)[x]
        >>> lcm(P(x**2 + 5), P(x-6))
        <Polynomial: x**3 + x, coeff_ring=F_(2**8)>

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
    
    Examples:
        >>> from samson.math.general import mod_inv
        >>> mod_inv(5, 11)
        9

    """
    from samson.math.algebra.rings.integer_ring import ZZ

    # For convenience
    peel_ring = False
    if type(a) is int:
        peel_ring = True
        a = ZZ(a)
        n = ZZ(n)

    _, x, _ = xgcd(a, n)
    R = a.ring

    if (a * x) % n != R.one():
        raise NotInvertibleException("'a' is not invertible", parameters={'a': a, 'x': x, 'n': n})

    if x < R.zero():
        x = x + n

    if peel_ring:
        x = x.val

    return x


def square_and_mul(g: int, u: int, s: int=None) -> int:
    """
    Computes `s = g ^ u` over arbitrary rings.

    Parameters:
        g (int): Base.
        u (int): Exponent.
        s (int): The 'one' value of the ring.
    
    Returns:
        int: `g ^ u` within its ring.
    
    Examples:
        >>> from samson.math.general import mod_inv
        >>> square_and_mul(5, 10, 1)
        9765625

        >>> from samson.math.algebra.all import ZZ
        >>> from samson.math.symbols import Symbol
        >>> x = Symbol('x')
        >>> P = (ZZ/ZZ(127))[x]
        >>> square_and_mul(P(x+5), 6)
        <Polynomial: x**6 + ZZ(30)*x**5 + ZZ(121)*x**4 + ZZ(87)*x**3 + ZZ(104)*x**2 + ZZ(81)*x + ZZ(4), coeff_ring=ZZ/ZZ(127)>

    """
    invert = False
    if u < 0:
        invert = True
        u = -u

    s = s or g.ring.one()
    while u != 0:
        if u & 1:
            s = (s * g)
        u >>= 1
        g = (g * g)

    if invert:
        s = ~s
    return s


def fast_mul(a: int, b: int, s: int=None) -> int:
    """
    Computes `s = a * b` over arbitrary rings.

    Parameters:
        a (int): Element `a`.
        b (int): Multiplier.
        s (int): The 'zero' value of the ring.
    
    Returns:
        int: `a * b` within its ring.
    
    Examples:
        >>> from samson.math.general import fast_mul
        >>> fast_mul(5, 12, 0)
        60

        >>> from samson.math.algebra.all import ZZ
        >>> from samson.math.symbols import Symbol
        >>> x = Symbol('x')
        >>> P = (ZZ/ZZ(127))[x]
        >>> fast_mul(P(x+5), 5)
        <Polynomial: ZZ(5)*x + ZZ(25), coeff_ring=ZZ/ZZ(127)>

    """
    s = s if s is not None else a.ring.zero()
    if b < 0:
        b = -b
        a = -a

    while b != 0:
        if b & 1:
            s = (s + a)
        b >>= 1
        a = (a + a)
    return s


def kth_root(n: int, k: int) -> int:
    """
    Calculates the `k`-th integer root of `n`.

    https://stackoverflow.com/questions/23621833/is-cube-root-integer

    Parameters:
        n (int): Integer.
        k (int): Root (e.g. 2).
    
    Returns:
        int: `k`-th integer root of `n
    
    Examples:
        >>> from samson.math.general import kth_root
        >>> kth_root(1000, 3)
        10

        >>> kth_root(129, 7)
        3

    """
    lb, ub = 0, n #lower bound, upper bound
    while lb < ub:
        guess = (lb + ub) // 2
        if pow(guess, k) < n:
            lb = guess + 1
        else:
            ub = guess

    return lb


def crt(residues: list, moduli: list=None) -> (object, object):
    """
    Performs the Chinese Remainder Theorem and returns the computed `x` and modulus.

    Parameters:
        residues (list): Residues of `x` as QuotientElements or tuples.

    Returns:
        (RingElement, RingElement): Formatted as (computed `x`, modulus).
    
    Examples:
        >>> from samson.math.general import crt
        >>> from samson.math.algebra.all import ZZ
        >>> from samson.math.symbols import Symbol
        >>> x = Symbol('x')

        >>> n = 17
        >>> residues = [(17 % mod, mod) for mod in [2, 3, 5]]
        >>> crt(residues)
        (17, 30)

        >>> n = 17
        >>> residues = [(ZZ/ZZ(mod))(17) for mod in [2, 3, 5]]
        >>> crt(residues)
        (<IntegerElement: val=17, ring=ZZ>, <IntegerElement: val=30, ring=ZZ>)

        >>> P = (ZZ/ZZ(2))[x]
        >>> moduli = [P(x + 1), P(x**2 + x + 1), P(x**3 + x + 1)]
        >>> n = P[17]
        >>> residues = [(P/mod)(n) for mod in moduli]
        >>> crt(residues)
        (<Polynomial: x**4 + ZZ(1), coeff_ring=ZZ/ZZ(2)>, <Polynomial: x**6 + x**4 + x + ZZ(1), coeff_ring=ZZ/ZZ(2)>)

    """
    from samson.math.algebra.rings.integer_ring import ZZ

    peel_ring = False
    if type(residues[0]) is tuple:
        if type(residues[0][0]) is int:
            ring = ZZ
            peel_ring = True
        else:
            ring = residues[0][0].ring

        residues = [(ring/ring(mod))(res) for res, mod in residues]

    x  = residues[0].val
    Nx = residues[0].ring.quotient
    ring = Nx.ring

    for i in range(1, len(residues)):
        modulus = residues[i].ring.quotient
        x  = (mod_inv(Nx, modulus) * (residues[i].val - x)) * Nx + x
        Nx = Nx * modulus

    x = x % Nx
    if peel_ring:
        x, Nx = x.val, Nx.val

    return x, Nx


class ResidueSymbol(Enum):
    EXISTS = 1
    DOES_NOT_EXIST = -1
    IS_ZERO = 0


def legendre(a: int, p: int) -> ResidueSymbol:
    """
    Calculates the Legendre symbol of `a` mod `p`. Nonzero quadratic residues mod `p` return 1 and nonzero, non-quadratic residues return -1. Zero returns 0.

    Parameters:
        a (int): Possible quadatric residue.
        p (int): Modulus.
    
    Returns:
        ResidueSymbol: Legendre symbol.
    
    Examples:
        >>> from samson.math.general import legendre
        >>> legendre(4, 7)
        <ResidueSymbol.EXISTS: 1>

        >>> legendre(5, 7)
        <ResidueSymbol.DOES_NOT_EXIST: -1>

    """
    result = pow(a, (p - 1) // 2, p)
    if result == p-1:
        result = -1

    return ResidueSymbol(result)


def generalized_eulers_criterion(a: int, k: int, p: int) -> ResidueSymbol:
    """
    Determines if `a` is a `k`-th root over `p`.

    Parameters:
        a (int): Possible `k`-th residue.
        k (int): Root to take.
        p (int): Modulus.
    
    Returns:
        ResidueSymbol: Legendre symbol (basically).

    Examples:
        >>> from samson.math.general import generalized_eulers_criterion
        >>> generalized_eulers_criterion(4, 2, 7)
        <ResidueSymbol.EXISTS: 1>

        >>> generalized_eulers_criterion(5, 2, 7)
        <ResidueSymbol.DOES_NOT_EXIST: -1>

        >>> generalized_eulers_criterion(4, 3, 11)
        <ResidueSymbol.EXISTS: 1>

    """
    result = pow(a, (p-1) // gcd(k, p-1), p)
    if result > 1:
        result = -1

    return ResidueSymbol(result)



def tonelli(n: int, p: int) -> int:
    """
    Performs the Tonelli-Shanks algorithm for calculating the square root of `n` mod `p`.

    https://crypto.stackexchange.com/questions/22919/explanation-of-each-of-the-parameters-used-in-ecc
    https://www.geeksforgeeks.org/find-square-root-modulo-p-set-2-shanks-tonelli-algorithm/
    https://rosettacode.org/wiki/Tonelli-Shanks_algorithm#Python

    Parameters:
        n (int): Integer.
        p (int): Modulus.
    
    Returns:
        int: Square root of `n` mod `p`.
    
    Examples:
        >>> from samson.math.general import tonelli
        >>> tonelli(4, 7)
        2

        >>> tonelli(2, 7)
        4

    """
    assert legendre(n, p) == ResidueSymbol.EXISTS, "not a square (mod p)"
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1

    if s == 1:
        return pow(n, (p + 1) // 4, p)

    for z in range(2, p):
        if legendre(z, p) == ResidueSymbol.DOES_NOT_EXIST:
            break

    c = pow(z, q, p)
    r = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)

    m  = s
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



def tonelli_q(a: int, p: int, q: int) -> int:
    """
    Performs the Tonelli-Shanks algorithm for calculating the `q`th-root of `n` mod `p`.

    From "On Taking Roots in Finite Fields" (https://www.cs.cmu.edu/~glmiller/Publications/AMM77.pdf)

    Parameters:
        n (int): Integer.
        p (int): Modulus.
        q (int): Root to take.

    Returns:
        int: `q`th-root of `n` mod `p`.

    Examples:
        >>> from samson.math.general import tonelli_q
        >>> tonelli_q(4, 7, 2)
        2

        >>> tonelli_q(2, 7, 2)
        4

        >>> tonelli_q(8, 67, 3)
        58

        >>> 58**3 % 67
        8

    """
    # Step 1 & 2
    assert generalized_eulers_criterion(a, q, p) == ResidueSymbol.EXISTS, "not a power (mod p)"

    # Step 3
    for g in range(2, p):
        if generalized_eulers_criterion(g, q, p) == ResidueSymbol.DOES_NOT_EXIST:
            break

    # Step 4
    p_1 = p - 1
    k   = 0

    # The algorithm only works if q | p-1
    assert p_1 % q == 0

    n = q
    div = gcd(q, p-1)
    while div != 1 and div != n:
        n   = n // div
        div = gcd(n, p-1)


    if p_1 % n == 0:
        k = 1
        p_1 //= n

    N, N_prime = divmod(p_1, n)

    # Step 5
    l = 1

    while True:
        # Step 6
        for j in range(k):
            if pow(a, q**j*(q*N+N_prime), p) == 1:
                break

        # Step 7
        if j == 0:
            # Step 8
            return pow(a, mod_inv(n, n*N+N_prime), p) * mod_inv(l, p)
        else:
            for lamb in range(1, n):
                if gcd(lamb, n) == 1:
                    if (pow(a, pow(2, j-1)*pow(2, N+N_prime), p) * pow(g, lamb*pow(2, k-1)*(2*N+N_prime), p)) % p == 1:
                        break

            a = (a * pow(g, pow(2, (k-j  )*lamb), p)) % p
            l = (l * pow(g, pow(2, (k-j-1)*lamb), p)) % p



def lll(in_basis: list, delta: float=0.75) -> Matrix:
    """
    Performs the Lenstra–Lenstra–Lovász lattice basis reduction algorithm.

    https://github.com/orisano/olll/blob/master/olll.py
    https://en.wikipedia.org/wiki/Lenstra%E2%80%93Lenstra%E2%80%93Lov%C3%A1sz_lattice_basis_reduction_algorithm

    Parameters:
        in_basis (list): List of Matrix objects representing the original basis.
        delta   (float): Minimum optimality of the reduced basis.

    Returns:
        Matrix: Reduced basis.
    
    Examples:
        >>> from samson.math.general import lll
        >>> from sympy.matrices import Matrix, eye
        >>> m = Matrix([[1, 2, 3, 4], [5, 6, 7, 8]])
        >>> lll([m.row(row) for row in range(m.rows)])
        Matrix([
        [ 3, 2, 1, 0],
        [-2, 0, 2, 4]])

    """
    basis = deepcopy(in_basis)
    n     = len(basis)
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
    
    Examples:
        >>> from samson.math.general import generate_superincreasing_seq
        >>> generate_superincreasing_seq(10, 2)
        [...]

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
    
    Examples:
        >>> from samson.math.general import find_coprime
        >>> find_coprime(10, range(500, 1000))
        501

    """
    for i in search_range:
        if gcd(p, i) == 1:
            return i



def random_int(n: int) -> int:
    """
    Finds a unbiased, uniformly-random integer between 0 and `n`-1.

    Parameters:
        n (int): Upper bound.
    
    Returns:
        int: Random integer.
    
    Example:
        >>> from samson.math.general import random_int
        >>> random_int(1000) < 1000
        True

    """
    byte_length = math.ceil(n.bit_length() / 8)
    max_bit = 2**n.bit_length()
    q = max_bit // n
    max_num = n * q - 1
    while True:
        attempt = int.from_bytes(rand_bytes(byte_length), 'big') % max_bit
        if attempt <= max_num:
            return attempt % n



def find_prime(bits: int, ensure_halfway: bool=True) -> int:
    """
    Finds a prime of `bits` bits.

    Parameters:
        bits            (int): Bit length of prime.
        ensure_halfway (bool): Ensures the prime is at least halfway into the bitspace to prevent multiplications being one bit short (e.g. 256-bit int * 256-bit int = 511-bit int).
    
    Returns:
        int: Random prime number.
    
    Examples:
        >>> from samson.math.general import find_prime
        >>> find_prime(512) < 2**512
        True

    """
    rand_num = random_int(2**bits)
    rand_num |= 2**(bits - 1)

    if ensure_halfway:
        rand_num |= 2**(bits - 2)

    return next_prime(rand_num)



def next_prime(start_int: int) -> int:
    """
    Finds the next prime.

    Parameters:
        start_int (int): Integer to start search at.
    
    Returns:
        int: Prime.
    
    Examples:
        >>> from samson.math.general import next_prime
        >>> next_prime(8)
        11

        >>> next_prime(11+1)
        13

    """
    start_int |= 1
    while not is_prime(start_int):
        start_int += 2

    return start_int



def berlekamp_massey(output_list: list) -> object:
    """
    Performs the Berlekamp-Massey algorithm to find the shortest LFSR for a binary output sequence.

    https://en.wikipedia.org/wiki/Berlekamp%E2%80%93Massey_algorithm

    Parameters:
        output_list (list): Output of LFSR.
    
    Returns:
        Polynomial: Polyomial that represents the shortest LFSR.
    
    Examples:
        >>> from samson.prngs.flfsr import FLFSR
        >>> from samson.math.general import berlekamp_massey
        >>> from samson.math.all import Polynomial, ZZ
        >>> from samson.math.symbols import Symbol
        >>> x = Symbol('x')
        >>> _ = (ZZ/ZZ(2))[x]
        >>> lfsr = FLFSR(3, x**25 + x**20 + x**12 + x**8  + 1)
        >>> outputs = [lfsr.generate() for _ in range(50)]
        >>> berlekamp_massey(outputs)
        <Polynomial: x**25 + x**17 + x**13 + x**5 + ZZ(1), coeff_ring=ZZ/ZZ(2)>

    """
    from samson.math.algebra.rings.integer_ring import ZZ
    from samson.math.polynomial import Polynomial
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

    return Polynomial(c[:L + 1][::-1], coeff_ring=ZZ/ZZ(2))


def is_power_of_two(n: int) -> bool:
    """
    Determines if `n` is a power of two.

    Parameters:
        n (int): Integer.
    
    Returns:
        bool: Whether or not `n` is a power of two.
    
    Examples:
        >>> from samson.math.general import is_power_of_two
        >>> is_power_of_two(7)
        False

        >>> is_power_of_two(8)
        True

    """
    return n != 0 and (n & (n - 1) == 0)


def totient(n: int, factors: dict=None) -> int:
    """
    Calculates Euler's totient of `n`. The totient is the number of elements coprime to `n`.

    Parameters:
        n        (int): Number to find the totient of.
        factors (dict): Factors of `n`.
    
    Returns:
        int: Totient of `n`.
    """
    if not factors:
        factors = factor(n)

    t = 1
    for p, e in factors.items():
        t *= (p-1) * p**(e-1)

    return t


def pollards_kangaroo(g: object, y: object, a: int, b: int, iterations: int=30, f: FunctionType=None, apply_reduction: bool=True) -> int:
    """
    Probabilistically finds the discrete logarithm of base `g` in GF(`p`) of `y` in the interval [`a`, `b`].

    https://en.wikipedia.org/wiki/Pollard%27s_kangaroo_algorithm

    Parameters:
        g             (object): Generator.
        y             (object): Number to find the discrete logarithm of.
        a                (int): Interval start.
        b                (int): Interval end.
        iterations       (int): Number of times to run the outer loop. If `f` is None, it's used in the pseudorandom map.
        f               (func): Pseudorandom map function of signature (y: RingElement, k: int) -> int.
        apply_reduction (bool): Whether or not to reduce the answer by the ring's order.
    
    Returns:
        int: The discrete logarithm. Possibly None if it couldn't be found.
    
    Examples:
        >>> from samson.math.general import pollards_kangaroo
        >>> from samson.math.algebra.all import *
        >>> p = find_prime(2048) 
        >>> g, x = 5, max(random_int(p), 1) 
        >>> R = (ZZ/ZZ(p)).mul_group() 
        >>> g = R(g) 
        >>> y = g*x 
        >>> dlog = pollards_kangaroo(g, y, x-1000, x+1000)
        >>> g * dlog == y
        True

        >>> p =  53
        >>> ring = ZZ/ZZ(p)
        >>> curve = WeierstrassCurve(a=50, b=7, ring=ring, base_tuple=(34, 25))
        >>> start, end = hasse_frobenius_trace_interval(curve.p)
        >>> dlog = pollards_kangaroo(g=curve.G, y=curve.POINT_AT_INFINITY, a=start + curve.p, b=end + curve.p)
        >>> curve.G * dlog == curve.zero()
        True

    """
    k = iterations
    R = g.ring

    # This pseudorandom map function has the following desirable properties:
    # 1) Never returns zero. Zero can form an infinite loop
    # 2) Works across all rings
    if not f:
        n = kth_root(b-a, 2)
        f = lambda y, k: pow(2, hash(y) % k, n)

    while k > 1:
        N = (f(g, k) + f(g*b, k)) // 2 * 4

        # Tame kangaroo
        xT = 0
        yT = g*b

        for _ in range(N):
            f_yT  = f(yT, k)
            xT   += f_yT
            yT   += g*f_yT


        # Wild kangaroo
        xW = 0
        yW = y

        while xW < b - a + xT:
            f_yW = f(yW, k)
            xW  += f_yW
            yW  += g*f_yW

            if yW == yT:
                result = b + xT - xW

                if apply_reduction:
                    result %= R.order

                return result


        # Didn't find it. Try another `k`
        k -= 1

    raise ProbabilisticFailureException("Discrete logarithm not found")




def hasse_frobenius_trace_interval(p: int) -> (int, int):
    """
    Finds the interval relative to `p` in which the Frobenius trace must reside according to Hasse's theorem.

    Parameters:
        p (int): Prime of the underlying field of the elliptic curve.
    
    Returns:
        (int, int): Start and end ranges of the interval relative to `p`.
    
    Examples:
        >>> from samson.math.general import hasse_frobenius_trace_interval
        >>> hasse_frobenius_trace_interval(53)
        (-16, 17)

    """
    l = 2 * math.ceil(math.sqrt(p))
    return (-l , l + 1)



def primes_product(n: int, blacklist: list=None) -> list:
    """
    Returns a list of small primes whose product is greater than or equal to `n`.

    Parameters:
        n          (int): Product to find.
        blacklist (list): Primes to skip.
    
    Returns:
        list: List of primes.
    
    Examples:
        >>> from samson.math.general import primes_product
        >>> primes_product(100, [2])
        [7, 5, 3]

    """
    total     = 1
    primes    = []
    blacklist = blacklist if blacklist else []

    for prime in sieve.primerange(2, n.bit_length()*2+1):
        if total >= n:

            # We might be able to remove some of the large primes
            primes.reverse()
            needed_primes = []
            for prime in primes:
                if total // prime >= n:
                    total //= prime
                else:
                    needed_primes.append(prime)

            return needed_primes

        if prime not in blacklist:
            primes.append(prime)
            total *= prime



def find_representative(quotient_element: object, valid_range: list) -> int:
    """
    Finds the representative element of `quotient_element` within `valid_range`.

    Parameters:
        quotient_element (QuotientElement): Element to search for.
        valid_range                 (list): Range to search in.
    
    Returns:
        int: Representative element.
    
    Examples:
        >>> from samson.math.all import *
        >>> find_representative((ZZ/ZZ(11))(3), range(11, 22))
        14

    """
    remainder = int(quotient_element)
    modulus   = int(quotient_element.ring.quotient)

    if len(valid_range) > modulus:
        raise ValueError("Solution not unique")

    q, r = divmod(valid_range[0], modulus)
    shifted_range = range(r, r + len(valid_range))

    if remainder in shifted_range:
        return q * modulus + remainder

    elif remainder + modulus in shifted_range:
        return (q+1) * modulus + remainder

    else:
        raise ValueError("No solution")



def frobenius_endomorphism(point: object, q: int) -> object:
    """
    Computes the Frobenius endomorphism of the `point`.

    Parameters:
        point (object): Original point.
        q        (int): Power to raise to.
    
    Returns:
        object: Resultant point.
    """
    return point.__class__(x=point.x**q, y=point.y**q, curve=point.curve)



def frobenius_trace_mod_l(curve: object, l: int) -> object:
    """
    Finds the Frobenius trace modulo `l` for faster computation.

    Parameters:
        curve (object): Elliptic curve.
        l        (int): Prime modulus.

    Returns:
        QuotientElement: Modular residue of the Frobenius trace.
    """
    from samson.math.algebra.curves.weierstrass_curve import WeierstrassCurve
    from samson.math.algebra.fields.fraction_field import FractionField as Frac
    from samson.math.algebra.rings.integer_ring import ZZ

    torsion_quotient_ring = ZZ/ZZ(l)
    psi = curve.division_poly(l)

    # Build symbolic torsion group
    R = curve.curve_poly_ring
    S = R/psi
    T = Frac(S, simplify=False)
    sym_curve = WeierstrassCurve(a=curve.a, b=curve.b, ring=T)

    x = R.poly_ring.symbol

    p_x = T(R((x, 0)))
    p_y = T(R((0, 1)))

    point = sym_curve(p_x, p_y)

    # Generate symbolic points
    p1 = frobenius_endomorphism(point, curve.p)
    p2 = frobenius_endomorphism(p1, curve.p)
    determinant = (curve.p % l) * point

    point_sum = determinant + p2

    # Find trace residue
    if point_sum == sym_curve.POINT_AT_INFINITY:
        return torsion_quotient_ring(0)

    trace_point = p1
    for candidate in range(1, (l + 1) // 2):
        if point_sum.x == trace_point.x:
            if point_sum.y == trace_point.y:
                return torsion_quotient_ring(candidate)
            else:
                return torsion_quotient_ring(-candidate)
        else:
            trace_point += p1

    raise ArithmeticError("No trace candidate satisfied the Frobenius equation")



def frobenius_trace(curve: object) -> int:
    """
    Calculates the Frobenius trace of the `curve`.

    Parameters:
        curve (object): Elliptic curve.
    
    Returns:
        int: Frobenius trace.
    
    Examples:
        >>> from samson.math.general import frobenius_trace
        >>> from samson.math.algebra.all import *

        >>> ring = ZZ/ZZ(53)
        >>> curve = WeierstrassCurve(a=50, b=7, ring=ring, base_tuple=(34, 25))
        >>> frobenius_trace(curve)
        -3

    """
    from samson.math.algebra.rings.integer_ring import ZZ
    from samson.math.symbols import Symbol

    search_range      = hasse_frobenius_trace_interval(curve.p)
    torsion_primes    = primes_product(search_range[1] - search_range[0], [curve.ring.characteristic])
    trace_congruences = []

    # Handle 2 separately to prevent multivariate poly arithmetic
    if 2 in torsion_primes:
        x = Symbol('x')
        _ = curve.ring[x]

        defining_poly = x**3 + curve.a*x + curve.b
        bases         = frobenius_monomial_base(defining_poly)
        rational_char = bases[1]
        rational_char = frobenius_map(rational_char, defining_poly, bases=bases)

        if gcd(rational_char - x, defining_poly).degree() == 0:
            trace_congruences.append((ZZ/ZZ(2))(1))
        else:
            trace_congruences.append((ZZ/ZZ(2))(0))

        torsion_primes.remove(2)


    for l in torsion_primes:
        trace_congruences.append(frobenius_trace_mod_l(curve, l))

    n, mod = crt(trace_congruences)
    return find_representative((ZZ/ZZ(mod))(n), range(*search_range))


def schoofs_algorithm(curve: object) -> int:
    """
    Performs Schoof's algorithm to count the number of points on an elliptic curve.

    Parameters:
        curve (object): Elliptic curve to find cardinality of.
    
    Returns:
        int: Curve cardinality.
    
    Examples:
        >>> from samson.math.general import schoofs_algorithm
        >>> from samson.math.algebra.all import *

        >>> ring = ZZ/ZZ(53)
        >>> curve = WeierstrassCurve(a=50, b=7, ring=ring, base_tuple=(34, 25))
        >>> schoofs_algorithm(curve)
        57

    """
    return curve.p + 1 - frobenius_trace(curve)


def bsgs(g: object, h: object, end: int, e: object=None, start: int=0) -> int:
    """
    Performs Baby-step Giant-step with an arbitrary finite cyclic group.

    Parameters:
        g  (object): Generator/base.
        h  (object): The result to find the discrete logarithm of.
        end   (int): End of the search range.
        e  (object): Starting point of the aggregator.
        start (int): Start of the search range.

    Returns:
        int: The discrete logarithm of `h` given `g`.

    Examples:
        >>> from samson.math.general import hasse_frobenius_trace_interval, bsgs, mod_inv
        >>> from samson.math.algebra.all import *

        >>> ring = ZZ/ZZ(53)
        >>> curve = WeierstrassCurve(a=50, b=7, ring=ring, base_tuple=(34, 25))
        >>> start, end = hasse_frobenius_trace_interval(curve.p)
        >>> bsgs(curve.G, curve.POINT_AT_INFINITY, e=curve.POINT_AT_INFINITY, start=start + curve.p, end=end + curve.p)
        57

        >>> ring = ZZ/ZZ(53)
        >>> mul = ring.mul_group()
        >>> base = mul(7)
        >>> exponent = 24
        >>> h = base * exponent
        >>> bsgs(base, h, int(ring.quotient))
        24

    """
    search_range = end - start
    table        = {}
    m            = kth_root(search_range, 2)

    if not e:
        e = g.ring.zero()

    for i in range(m):
        table[e] = i
        e += g

    factor = g * m
    o = g * start
    e = h
    for i in range(m):
        e = h - o
        if e in table:
            return i*m + table[e] + start

        o += factor

    raise SearchspaceExhaustedException("This shouldn't happen; check your arguments")



def pohlig_hellman(g: object, h: object, n: int, factors: dict=None) -> int:
    """
    Computes the discrete logarithm for finite abelian groups with a smooth order.

    https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm

    Parameters:
        g     (object): Generator element.
        h     (object): Result to find discrete logarithm of.
        n        (int): Order of the group.
        factors (dict): `n`'s factorization.

    Returns:
        int: The discrete logarithm of `h` given `g`.

    Examples:
        >>> from samson.math.general import pohlig_hellman
        >>> from samson.math.algebra.all import *

        >>> p    = 7
        >>> ring = (ZZ/ZZ(p)).mul_group()
        >>> g    = ring(3)
        >>> exp  = 2
        >>> h    = g * exp
        >>> pohlig_hellman(g, h, p-1)
        2

        >>> p    = 2**127-1
        >>> ring = (ZZ/ZZ(p)).mul_group()
        >>> g    = ring(5)
        >>> exp  = 25347992192497823499464681366516589049
        >>> h    = g * exp
        >>> exp2 = pohlig_hellman(g, h, p-1)
        >>> g * exp2 == h
        True

        >>> ring  = ZZ/ZZ(53)
        >>> curve = WeierstrassCurve(a=50, b=7, ring=ring, base_tuple=(34, 25))
        >>> g     = curve.G
        >>> exp   = 28
        >>> h     = g * exp
        >>> pohlig_hellman(curve.G, h, curve.G.order)
        28

    """
    if not factors:
        factors = factor(n)

    x = [0] * len(factors)

    for i, (p, e) in enumerate(factors.items()):
        gamma = g * (n // p)
        for k in range(e):
            g_k = g * x[i]
            h_k = (h + -g_k) * (n // p**(k+1))
            d_k = bsgs(gamma, h_k, p)
            x[i] += d_k * p**k

    return crt(list(zip(x, [p**e for p, e in  factors.items()])))[0]



def miller_rabin(n: int, k: int=64, bases: list=None) -> bool:
    """
    Probabilistic primality test. Each iteration has a 1/4 false positive rate.
    Always returns a false positive on Carmichael numbers.

    https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test#Miller%E2%80%93Rabin_test

    Parameters:
        n (int): Number to determine if probably prime.
        k (int): Number of iterations to run.
    
    Returns:
        bool: Whether `n` is probably prime.

    Examples:
        >>> from samson.math.general import miller_rabin
        >>> miller_rabin(127)
        True

        >>> miller_rabin(6)
        False

    """
    n_1 = n - 1
    d   = n_1
    r   = 0
    while not d % 2 and d:
        r += 1
        d //= 2

    if not bases:
        def generator():
            for _ in range(k):
                yield max(2, random_int(n_1))

        bases = generator()

    for a in bases:
        x = pow(a, d, n)
        if x == 1 or x == n_1:
            continue

        found = False
        for _ in range(r-1):
            x = pow(x, 2, n)
            if x == n_1:
                found = True
                break

        if not found:
            return False

    return True


FB_LARGE_MOD = 3989930175
def is_square(n: int) -> bool:
    """
    Determines if `n` is a square using "fenderbender" tests first.

    https://mersenneforum.org/showpost.php?p=110896

    Parameters:
        n (int): Number to test.

    Returns:
        bool: Whether or not `n` is a square.
    
    Examples:
        >>> from samson.math.general import is_square
        >>> p = 18431211066281663581
        >>> is_square(p**2)
        True

        >>> is_square(6)
        False

    """
    if n in [0, 1]:
        return True

    m = n % 128
    if ((m*0x8bc40d7d) & (m*0xa1e2f5d1) & 0x14020a):
        return False

    n_mod = n % FB_LARGE_MOD

    m = n_mod % 63
    if ((m*0x3d491df7) & (m*0xc824a9f9) & 0x10f14008):
        return False

    m = n_mod % 25
    if ((m*0x1929fc1b) & (m*0x4c9ea3b2) & 0x51001005):
         return False

    return kth_root(n, 2)**2 == n


def jacobi_symbol(n: int, k: int) -> ResidueSymbol:
    """
    Generalization of the Legendre symbol.

    https://en.wikipedia.org/wiki/Jacobi_symbol

    Parameters:
        n (int): Possible quadatric residue.
        k (int): Modulus (must be odd).
    
    Return:
        ResidueSymbol: Jacobi symbol.
    
    Examples:
        >>> from samson.math.general import jacobi_symbol
        >>> jacobi_symbol(4, 7)
        <ResidueSymbol.EXISTS: 1>

        >>> jacobi_symbol(5, 7)
        <ResidueSymbol.DOES_NOT_EXIST: -1>

    """
    assert k > 0 and k % 2 == 1
    n %= k
    t = 1

    while n != 0:
        while n % 2 == 0:
            n //= 2
            r = k % 8

            if r in [3, 5]:
                t = -t

        n, k = k, n
        if n % 4 == 3 and k % 4 == 3:
            t = -t

        n %= k

    if k == 1:
        return ResidueSymbol(t)
    else:
        return ResidueSymbol(0)


def generate_lucas_selfridge_parameters(n: int) -> (int, int, int):
    """
    Generates the Selfridge parameters to use in Lucas strong pseudoprime testing.

    Parameters:
        n (int): Possible prime.
    
    Returns:
        (int, int, int): Selfridge parameters.
    """
    D = 5
    while True:
        g = gcd(abs(D), n)
        if g > 1 and g != n:
            return (0, 0, 0)

        if jacobi_symbol(D, n) == ResidueSymbol.DOES_NOT_EXIST:
            break

        if D > 0:
            D = -D - 2
        else:
            D = -D + 2

    return (D, 1, (1-D) // 4)


def generate_lucas_sequence(n: int, P: int, Q: int, k: int) -> (int, int, int):
    """
    Generates a Lucas sequence. Used internally for the Lucas primality test.

    Adapted from https://docs.sympy.org/latest/_modules/sympy/ntheory/primetest.html#isprime
    """
    D = P**2 - 4*Q

    assert n > 1
    assert k >= 0
    assert D != 0

    if k == 0:
        return (0, 2, Q)

    U  = 1
    V  = P
    Qk = Q
    b  = k.bit_length()

    while b > 1:
        U = U*V % n
        V = (V*V - 2*Qk) % n
        Qk *= Qk
        b  -= 1

        if (k >> (b - 1)) & 1:
            U, V = U*P + V, V*P + U*D

            if U & 1:
                U += n

            if V & 1:
                V += n

            U >>= 1
            V >>= 1
            Qk *= Q

        Qk %= n

    return (U % n, V % n, Qk)


def is_strong_lucas_pseudoprime(n: int) -> bool:
    """
    Determines if `n` is at least a strong Lucas pseudoprime.

    Parameters:
        n (int): Integer to test.
    
    Returns:
        bool: Whether or not `n` is at least a strong Lucas pseudoprime.
    
    Examples:
        >>> from samson.math.general import is_strong_lucas_pseudoprime
        >>> is_strong_lucas_pseudoprime(299360470275914662072095298694855259241)
        True

        >>> is_strong_lucas_pseudoprime(128)
        False

    """
    if n == 2:
        return True

    if n < 2 or n % 2 == 0 or is_square(n):
        return False

    D, P, Q = generate_lucas_selfridge_parameters(n)
    if D == 0:
        return False

    s    = 0
    q, r = divmod(n+1, 2)
    k    = q
    while q and not r:
        k    = q
        s   += 1
        q, r = divmod(q, 2)

    U, V, Qk = generate_lucas_sequence(n, P, Q, k)
    if U == 0 or V == 0:
        return True

    for _ in range(s):
        V = (V**2 - 2*Qk) % n

        if V == 0:
            return True

        Qk = pow(Qk, 2, n)

    return False


PRIMES_UNDER_1000 = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997}

def is_prime(n: int) -> bool:
    """
    Determines if `n` is probably prime using the Baillie-PSW primality test.

    https://en.wikipedia.org/wiki/Baillie%E2%80%93PSW_primality_test

    Parameters:
        n (int): Positive integer.
    
    Returns:
        bool: Whether or not `n` is probably prime.
    
    Examples:
        >>> from samson.math.general import is_prime, find_prime
        >>> is_prime(7)
        True

        >>> is_prime(15)
        False

        >>> is_prime(find_prime(32))
        True

    """
    if n in PRIMES_UNDER_1000:
        return True

    for prime in PRIMES_UNDER_1000:
        if (n % prime) == 0:
            return False

    return miller_rabin(n, bases=[2]) and is_strong_lucas_pseudoprime(n)


def pollards_rho(n: int) -> int:
    """
    Uses Pollard's rho to find a factor of `n`.

    https://en.wikipedia.org/wiki/Pollard%27s_rho_algorithm

    Parameters:
        n (int): Integer to factor.
    
    Returns:
        int: Factor of `n`.
    
    Examples:
        >>> from samson.math.general import pollards_rho
        >>> pollards_rho(26515460203326943826)
        2

    """
    x = 2
    x_fixed = x
    cycle_size = 2
    factor = 1
    mod = 1

    while factor == 1:
        count = 1
        while count <= cycle_size and factor <= 1:
            x = (x*x + mod) % n
            factor = gcd(x - x_fixed, n)
            count += 1

            # If we get stuck on `n`, retry with -1
            if factor == n:
                factor = 1
                mod    = -1

        cycle_size *= 2
        x_fixed = x

    return factor


def ecm(n: int, attempts: int=None) -> int:
    """
    Uses Lenstra's Elliptic Curve Method to probabilistically find a factor of `n`.

    Parameters:
        n        (int): Integer to factor.
        attempts (int): Number of attempts to perform.
    
    Returns:
        int: Factor of `n`.
    
    Examples:
        >>> from samson.math.general import ecm
        >>> ecm(26515460203326943826)
        2

    """
    from samson.math.algebra.rings.integer_ring import ZZ
    from samson.math.algebra.curves.weierstrass_curve import WeierstrassCurve

    if not attempts:
        attempts = kth_root(n, 4)

    ring = ZZ/ZZ(n)
    for a in range(attempts):
        while True:
            x = random_int(n)
            y = random_int(n)
            a = random_int(n)
            b = (y**2 - x**3 - (a * x)) % n

            g = gcd(4 * a**3 - 27 * b**2, n)
            if g != n:
                break

        # Free factor!
        if g > 1:
            return g

        curve = WeierstrassCurve(a=a, b=b, ring=ring, base_tuple=(x, y))
        curr  = curve.G
        for fac in range(2, 64):
            try:
                curr *= fac
            except NotInvertibleException as e:
                return int(gcd(e.parameters['a'], n))

    raise ProbabilisticFailureException("Factor not found")



def factor(n: int, use_trial: bool=True, use_rho: bool=True, use_ecm: bool=False, limit: int=1000, visual: bool=False) -> list:
    """
    Factors an integer `n` into its prime factors.

    Parameters:
        n          (int): Integer to factor.
        use_trial (bool): Whether or not to use trial division.
        use_rho   (bool): Whether or not to use Pollard's rho factorization.
        use_ecm   (bool): Whether or not to use ECM factorization.
        visual    (bool): Whether or not to display progress bar.

    Returns:
        list: List of factors.
    
    Examples:
        >>> from samson.math.general import factor
        >>> factor(26515460203326943826) == {2: 1, 3262271209: 1, 4063957057: 1} # equality because pytest sorts dicts weird
        True

    """
    from tqdm import tqdm

    factors = {}

    # Handle negatives
    if n < 1:
        factors[-1] = 1
        n //= -1

    # Handle [0, 1] or prime
    if n < 2 or is_prime(n):
        factors[n] = 1
        return factors


    def calc_prog(x):
        return round(math.log(x, 2), 2)

    if visual:
        progress = tqdm(None, total=calc_prog(n), unit='bit')
        def progress_update(x):
            progress.update(calc_prog(x))
            progress.refresh()

        def progress_finish():
            progress.close()

    else:
        def progress_update(x):
            pass

        def progress_finish():
            pass

    try:
        # Trial division
        if use_trial:
            for prime in chain(PRIMES_UNDER_1000, sieve.primerange(1000, limit)):
                while not n % prime:
                    add_or_increment(factors, prime)
                    progress_update(prime)
                    n //= prime


        if use_rho and not (n == 1 or is_prime(n)):
            # Pollard's rho
            while not is_prime(n):
                n_fac = pollards_rho(n)
                if n_fac == n:
                    break

                add_or_increment(factors, n_fac)
                progress_update(n_fac)
                n //= n_fac

        if use_ecm and not (n == 1 or is_prime(n)):
            # Lenstra's ECM
            while not is_prime(n):
                n_fac = ecm(n)
                add_or_increment(factors, n_fac)
                progress_update(n_fac)
                n //= n_fac

    except KeyboardInterrupt:
        pass

    progress_finish()
    if n != 1:
        add_or_increment(factors, n)

    return factors
