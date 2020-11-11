from samson.utilities.general import rand_bytes
from samson.utilities.exceptions import NotInvertibleException, ProbabilisticFailureException, SearchspaceExhaustedException, NoSolutionException
from functools import reduce
from types import FunctionType
from copy import deepcopy
from enum import Enum
import math

# Resolve circular dependencies while reducing function-level imports
from samson.auxiliary.lazy_loader import LazyLoader
_integer_ring = LazyLoader('_integer_ring', globals(), 'samson.math.algebra.rings.integer_ring')
_poly         = LazyLoader('poly', globals(), 'samson.math.polynomial')
_mat          = LazyLoader('mat', globals(), 'samson.math.matrix')
_dense        = LazyLoader('dense', globals(), 'samson.math.dense_vector')
_factor_gen   = LazyLoader('factor_gen', globals(), 'samson.math.factorization.general')

def int_to_poly(integer: int, modulus: int=2) -> 'Polynomial':
    """
    Encodes an `integer` as a polynomial.

    Parameters:
        integer (int): Integer to encode.
        modulus (int): Modulus to reduce the integer over.
    
    Returns:
        Polynomial: Polynomial representation.
    
    Examples:
        >>> from samson.math.general import int_to_poly
        >>> int_to_poly(100)
        <Polynomial: x**6 + x**5 + x**2, coeff_ring=ZZ/ZZ(2)>

        >>> int_to_poly(128, 3)
        <Polynomial: x**4 + x**3 + 2*x**2 + 2, coeff_ring=ZZ/ZZ(3)>

    """
    Polynomial = _poly.Polynomial
    ZZ = _integer_ring.ZZ
    base_coeffs = []

    # Use != to handle negative numbers
    while integer != 0 and integer != -1:
        integer, r = divmod(integer, modulus)
        base_coeffs.append(r)

    return Polynomial(base_coeffs, ZZ/ZZ(modulus))


def poly_to_int(poly: 'Polynomial') -> int:
    """
    Encodes an polynomial as a integer.

    Parameters:
        poly (Polynomial): Polynomial to encode.
        modulus     (int): Modulus to reconstruct the integer with.
    
    Returns:
        int: Integer representation.
    
    Examples:
        >>> from samson.math.general import int_to_poly, _poly_to_int
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


def frobenius_monomial_base(poly: 'Polynomial') -> list:
    """
    Generates a list of monomials of x**(i*p) % g for range(`poly`.degrees()). Used with Frobenius map.

    Parameters:
        poly (Polynomial): Polynomial to generate bases for.

    Returns:
        list: List of monomial bases mod g.
    
    References:
        https://github.com/sympy/sympy/blob/d1301c58be7ee4cd12fd28f1c5cd0b26322ed277/sympy/polys/galoistools.py
    """
    from samson.math.symbols import oo

    n = poly.degree()
    if n == 0:
        return []

    P = poly.ring
    q = poly.coeff_ring.order if poly.coeff_ring.order != oo else poly.coeff_ring.characteristic
    bases = [None]*n
    bases[0] = P.one

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


def frobenius_map(f: 'Polynomial', g: 'Polynomial', bases: list=None) -> 'Polynomial':
    """
    Computes `f`**p % `g` using the Frobenius map.
    
    Parameters:
        f (Polynomial): Base.
        g (Polynomial): Modulus.
        bases   (list): Frobenius monomial bases. Will generate if not provided.

    Returns:
        Polynomial: `f`**p % `g`

    References:
        https://en.wikipedia.org/wiki/Finite_field#Frobenius_automorphism_and_Galois_theory
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


def gcd(*args) -> int:
    """
    Iteratively computes the greatest common denominator.

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
    total = args[0]
    if type(total) is int:
        def _gcd(a,b):
            while b:
                a, b = b, a % b
            return a
    else:
        def _gcd(a,b):
            return a.gcd(b)

    for arg in args[1:]:
        total = _gcd(total, arg)

    return total


def xgcd(a: int, b: int) -> (int, int, int):
    """
    Extended Euclidean algorithm form of GCD.
    `a`x + `b`y = gcd(`a`, `b`)

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
        (<Polynomial: x**2, coeff_ring=F_(2**8)>, <Polynomial: 1, coeff_ring=F_(2**8)>, <Polynomial: F_(2**8)(ZZ(0)), coeff_ring=F_(2**8)>)

    References:
        https://anh.cs.luc.edu/331/notes/xgcd.pdf
    """
    ZZ = _integer_ring.ZZ

    # For convenience
    peel_ring = False
    if type(a) is int:
        peel_ring = True
        a = ZZ(a)
        b = ZZ(b)

    R = a.ring

    # Generic xgcd
    prevx, x = R.one, R.zero; prevy, y = R.zero, R.one
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


def lcm(*args) -> int:
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
    def _lcm(a, b):
        return a // gcd(a, b) * b

    total = args[0]
    for arg in args[1:]:
        total = _lcm(total, arg)

    return total


def mod_inv(a: int, n: int) -> int:
    """
    Calculates the modular inverse.

    Parameters:
        a (int): Integer.
        n (int): Modulus.
    
    Returns:
        int: Modular inverse of `a` over `n`.
    
    Examples:
        >>> from samson.math.general import mod_inv
        >>> mod_inv(5, 11)
        9

    References:
        https://en.wikipedia.org/wiki/Euclidean_algorithm#Linear_Diophantine_equations
        https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
    """
    ZZ = _integer_ring.ZZ

    # For convenience
    peel_ring = False
    if type(a) is int:
        peel_ring = True
        a = ZZ(a)
        n = ZZ(n)

    _, x, _ = xgcd(a, n)
    R = a.ring

    if (a * x) % n != R.one:
        raise NotInvertibleException("'a' is not invertible", parameters={'a': a, 'x': x, 'n': n})

    if x < R.zero:
        x = x + n

    if peel_ring:
        x = x.val

    return x


def square_and_mul(g: int, u: int, s: int=None) -> int:
    """
    Computes `s` = `g` ^ `u` over arbitrary rings.

    Parameters:
        g (int): Base.
        u (int): Exponent.
        s (int): The 'one' value of the ring.
    
    Returns:
        int: `g` ^ `u` within its ring.
    
    Examples:
        >>> from samson.math.general import mod_inv
        >>> square_and_mul(5, 10, 1)
        9765625

        >>> from samson.math.algebra.all import ZZ
        >>> from samson.math.symbols import Symbol
        >>> x = Symbol('x')
        >>> P = (ZZ/ZZ(127))[x]
        >>> square_and_mul(P(x+5), 6)
        <Polynomial: x**6 + 30*x**5 + 121*x**4 + 87*x**3 + 104*x**2 + 81*x + 4, coeff_ring=ZZ/ZZ(127)>

    """
    invert = False
    if u < 0:
        invert = True
        u = -u

    s = s or g.ring.one
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
    Computes `s` = `a` * `b` over arbitrary rings.

    Parameters:
        a (int): Element `a`.
        b (int): Multiplier.
        s (int): The 'zero' value of the ring.
    
    Returns:
        int: `a` * `b` within its ring.
    
    Examples:
        >>> from samson.math.general import fast_mul
        >>> fast_mul(5, 12, 0)
        60

        >>> from samson.math.algebra.all import ZZ
        >>> from samson.math.symbols import Symbol
        >>> x = Symbol('x')
        >>> P = (ZZ/ZZ(127))[x]
        >>> fast_mul(P(x+5), 5)
        <Polynomial: 5*x + 25, coeff_ring=ZZ/ZZ(127)>

    """
    s = s if s is not None else a.ring.zero
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

    References:
        https://stackoverflow.com/questions/23621833/is-cube-root-integer
        https://github.com/sympy/sympy/blob/c0bfc81f3ffee97c6d6732ac5e5ccf399e5ab3e2/sympy/core/power.py#L84
        https://en.wikipedia.org/wiki/Newton%27s_method
    """
    # Estimate the root using floating point exponentiation
    # This typically is within 1e-10 of the actual root for large integers
    try:
        guess = round(n**(1/k))

    except OverflowError:
        # If we overflow the float's precision, we can use a bit of math
        # to calculate it at a lower precision and shift it.
        # This still tends to be highly accurate
        e = math.log2(n)/k
        if e > 53:
            shift = int(e - 53)
            guess = int(2.0**(e - shift) + 1) << shift
        else:
            guess = int(2.0**e)


    # Newton's method is more likely to screw up small numbers than converge
    if guess > 2**50:
        # Use Newton's method to rapidly converge on the root
        rprev, root, k_1 = -1, guess, k-1
        while root > 2:
            approx = root**k_1
            rprev, root = root, (k_1*root + n//approx) // k
            if abs(root - rprev) < 2:
                break
    else:
        root = guess



    t = root**k
    if t == n:
        return root

    # If we're very close, then try incrementing/decrementing
    diff = n-t
    try:
        if abs(diff)/n < 0.1:
            if diff > 0:
                while t < n:
                    root += 1
                    t     = root**k
            else:
                while t > n:
                    root -= 1
                    t     = root**k

            return root + (t < n)
    except OverflowError:
        pass


    # If we're still not there, use binary search to comb through the rest of the space
    ub = root
    lb = 0

    while lb < ub:
        guess = (lb + ub) // 2
        if pow(guess, k) < n:
            lb = guess + 1
        else:
            ub = guess

    return lb + (lb**k < n)


def kth_root_qq(n: int, k: int, precision: int=32) -> 'FractionFieldElement':
    """
    Calculates the `k`-th rational root of `n` to `precision` bits of precision.

    Parameters:
        n      (int/QQ): Integer.
        k         (int): Root (e.g. 2).
        precision (int): Bits of precision.

    Returns:
        FractionFieldElement: `k`-th rational root of `n

    Examples:
        >>> from samson.math.general import kth_root_qq
        >>> kth_root_qq(2, 2, 32)
        <FractionFieldElement: numerator=759250125, denominator=536870912, ring=Frac(ZZ)>

        >>> diff = abs(float(kth_root_qq(2, 2, 32)) - 2**(0.5))

        >>> diff < 1/2**32
        True

        >>> diff < 1/2**64
        False

    References:
        https://stackoverflow.com/a/39802349
    """
    from samson.math.all import QQ

    n  = QQ(n)
    lb = QQ.zero
    ub = n
    precision = QQ((1, 2**precision))

    while True:
        mid = (lb+ub)/2
        mid_k = mid**k

        if abs(mid_k-n) < precision:
            return mid
        elif mid_k < n:
            lb = mid
        else:
            ub = mid



def crt(residues: list, auto_correct: bool=True) -> (object, object):
    """
    Performs the Chinese Remainder Theorem and returns the computed `x` and modulus.

    Parameters:
        residues     (list): Residues of `x` as QuotientElements or tuples.
        auto_correct (bool): Whether or not to automatically remove redundancy.

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
        (<Polynomial: x**4 + 1, coeff_ring=ZZ/ZZ(2)>, <Polynomial: x**6 + x**4 + x + 1, coeff_ring=ZZ/ZZ(2)>)

    """
    ZZ = _integer_ring.ZZ

    # Auto promote
    peel_ring = False
    if type(residues[0]) is tuple:
        if type(residues[0][0]) is int:
            ring = ZZ
            peel_ring = True
        else:
            ring = residues[0][0].ring

        residues = [(ring/ring(mod))(res) for res, mod in residues]


    # Remove redundancies
    if auto_correct:
        _tmp_res = [(res.val, res.ring.quotient) for res in residues]
        ring     = _tmp_res[0][0].ring

        x, Nx = _tmp_res[0]
        for r, n in _tmp_res[1:]:
            n_total = lcm(Nx, n)
            new_res = []

            n2p = n_total // Nx
            n1p = n_total // n

            if ring.one in [n1p, n2p]:
                if n > Nx:
                    x, Nx = r, n
            else:
                new_res.append((ring/n2p)(r))
                new_res.append((ring/n1p)(x))

                x, Nx = _crt(new_res)
    else:
        x, Nx = _crt(residues)

    if peel_ring:
        x, Nx = x.val, Nx.val

    return x, Nx



def _crt(residues: list) -> (object, object):
    x    = residues[0].val
    Nx   = residues[0].ring.quotient

    for i in range(1, len(residues)):
        modulus = residues[i].ring.quotient
        x  = (mod_inv(Nx, modulus) * (residues[i].val - x)) * Nx + x
        Nx = Nx * modulus

    x = x % Nx

    return x, Nx


def crt_lll(residues: list, remove_redundant: bool=True) -> 'QuotientElement':
    """
    Imitates the Chinese Remainder Theorem using LLL and returns the computed `x`.
    Unlike CRT, this does not require the moduli be coprime. However, this method only
    returns a representative since the solution isn't unique.

    Parameters:
        residues         (list): Residues of `x` as QuotientElements.
        remove_redundant (bool): Whether or not to remove redundant subgroups to minimize the result.

    Returns:
        QuotientElement: Computed `x` over composite modulus.

    Examples:
        >>> from samson.math.general import crt_lll
        >>> from samson.math.all import ZZ
        >>> x = 684250860
        >>> rings = [ZZ/ZZ(quotient) for quotient in [229, 246, 93, 22, 408]]
        >>> crt_lll([r(x) for r in rings])
        <QuotientElement: val=684250860, ring=ZZ/ZZ(1306272792)>

    References:
        https://grocid.net/2016/08/11/solving-problems-with-lattice-reduction/
    """
    from samson.math.algebra.fields.fraction_field import FractionField as Frac
    import operator
    Matrix = _mat.Matrix

    R = residues[0].ring.ring
    Q = Frac(R)

    # Remove redundant subgroups to minimize result
    if remove_redundant:
        reduc_func = lcm
    else:
        reduc_func = operator.mul

    # Calculate composite modulus
    L = reduce(reduc_func, [r.ring.quotient for r in residues])


    # Build the problem matrix
    r_len = len(residues)

    A = Matrix([
        [Q.one for r in residues] + [Q((R.one, L)), Q.zero],
        *[[Q.zero]*idx + [Q(r.ring.quotient)] + [Q.zero]*(1+r_len-idx) for idx, r in enumerate(residues)],
        [Q.zero for r in residues] + [Q.one, Q.zero],
        [Q(-r.val) for r in residues] + [Q.zero, L]
    ], Q)


    B = A.LLL(0.99)

    return (R/R(L))((B[-1, -2] * L).numerator)


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
    assert is_prime(p)
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

    References:
        https://crypto.stackexchange.com/questions/22919/explanation-of-each-of-the-parameters-used-in-ecc
        https://www.geeksforgeeks.org/find-square-root-modulo-p-set-2-shanks-tonelli-algorithm/
        https://rosettacode.org/wiki/Tonelli-Shanks_algorithm#Python
    """
    leg = legendre(n, p)
    if leg == ResidueSymbol.IS_ZERO:
        return 0

    elif leg == ResidueSymbol.DOES_NOT_EXIST:
        raise NoSolutionException()

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
    Performs the Tonelli-Shanks algorithm for calculating the `q`th-root of `a` mod `p`.

    Parameters:
        a (int): Integer.
        p (int): Modulus.
        q (int): Root to take.

    Returns:
        int: `q`th-root of `a` mod `p`.

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

    References:
        "On Taking Roots in Finite Fields" (https://www.cs.cmu.edu/~glmiller/Publications/AMM77.pdf)
    """
    # Step 1 & 2
    gec = generalized_eulers_criterion(a, q, p)

    if gec == ResidueSymbol.IS_ZERO:
        return 0

    elif gec == ResidueSymbol.DOES_NOT_EXIST:
        raise NoSolutionException()


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



def gaussian_elimination(system_matrix: 'Matrix', rhs: 'Matrix') -> 'Matrix':
    """
    Solves `Ax = b` for `x` where `A` is `system_matrix` and `b` is `rhs`.

    Parameters:
        system_matrix (Matrix): The `A` matrix.
        rhs           (Matrix): The right-hand side matrix.
    
    Returns:
        Matrix: The `x` matrix.
    
    Examples:
        >>> from samson.math.all import QQ
        >>> from samson.math.matrix import Matrix
        >>> from samson.math.general import gaussian_elimination
        >>> a = Matrix([[3, 2,-4], [2, 3, 3], [5, -3, 1]], coeff_ring=QQ)
        >>> b = Matrix([[3], [15], [14]], coeff_ring=QQ)
        >>> c = gaussian_elimination(a, b)
        >>> a*c == b
        True

    References:
        https://rosettacode.org/wiki/Gaussian_elimination#Python
    """
    Matrix = _mat.Matrix

    A = deepcopy(system_matrix).row_join(rhs)

    n = A.num_rows
    m = A.num_cols
    R = A.coeff_ring

    # Forward elimination
    for i in range(n):
        # Find pivot
        k = max(range(i, n), key=lambda r: max(A[r][i], -A[r][i]))

        if not A[k, i]:
            continue

        # Swap rows
        A[i], A[k] = A[k], A[i]

        # Reduce rows
        scalar = ~A[i, i]
        for j in range(i+1, n):
            A[j] = [A[j, k] - A[i, k] * A[j, i] * scalar for k in range(m)]


    # Back substitution
    # This works with any size matrix
    rhs_cols = m - rhs.num_cols
    for i in reversed(range(n)):
        for j in range(i + 1, n):
            t = A[i, j]
            for k in range(rhs_cols, m):
                A[i, k] -= t*A[j, k]

        if not A[i, i]:
            continue

        t = ~A[i, i]

        for j in range(rhs_cols, m):
            A[i, j] *= t

    return Matrix(A[:, rhs_cols:m], coeff_ring=R, ring=A.ring)


def gram_schmidt(matrix: 'Matrix', full: bool=False) -> 'Matrix':
    """
    Performs Gram-Schmidt orthonormalization.

    Parameters:
        matrix  (Matrix): Matrix of row vectors.
        normalize (bool): Whether or not to normalize the vectors.

    Returns:
        Matrix: Orthonormalized row vectors.

    Examples:
        >>> from samson.math.all import QQ
        >>> from samson.math.matrix import Matrix
        >>> from samson.math.general import gram_schmidt
        >>> out, _ = gram_schmidt(Matrix([[3,1],[2,2]], QQ))
        >>> [[float(out[r][c]) for c in range(out.num_cols)] for r in range(out.num_rows)]
        [[3.0, 1.0], [-0.4, 1.2]]

    References:
        https://github.com/sagemath/sage/blob/854f9764d14236110b8d7f7b35a7d52017e044f8/src/sage/modules/misc.py
        https://github.com/sagemath/sage/blob/1d465c7e3c82110d39034f3ca7d9d120f435511e/src/sage/matrix/matrix2.pyx

    """
    Matrix = _mat.Matrix
    DenseVector = _dense.DenseVector

    R = matrix.coeff_ring
    n = matrix.num_rows
    A = matrix
    A_star = []

    mu = Matrix([[R.zero for _ in range(n)] for _ in range(n)])

    # Number of non-zero rows
    nnz = 0
    zeroes = []

    # Orthogonalization
    for j in range(n):
        ortho = A[j]

        for k in range(nnz):
            mu[j,k] = A_star[k].dot(A[j]) / A_star[k].sdot()
            ortho  -= A_star[k]*mu[j,k]

        if ortho.sdot() != R.zero:
            A_star.append(ortho)
            mu[j ,nnz] = R.one
            nnz += 1
        else:
            zeroes.append(j+len(zeroes))


    # Manipulating result matrices with zero vectors
    if not full:
        mu = Matrix([row for row in mu.T if any(row)]).T

    if full:
        zero = [DenseVector([R.zero for _ in range(n-len(zeroes))])]
        for j in zeroes:
            A_star = A_star[:j] + zero + A_star[j:]

    Q = Matrix([v.values for v in A_star])
    return Q, mu


def lll(in_basis: 'Matrix', delta: float=0.75) -> 'Matrix':
    """
    Performs the Lenstra–Lenstra–Lovász lattice basis reduction algorithm.

    Parameters:
        in_basis (Matrix): Matrix representing the original basis.
        delta     (float): Minimum optimality of the reduced basis.

    Returns:
        Matrix: Reduced basis.

    Examples:
        >>> from samson.math.general import lll
        >>> from samson.math.matrix import Matrix
        >>> from samson.math.all import QQ
        >>> m = Matrix([[1, 2, 3, 4], [5, 6, 7, 8]], QQ)
        >>> lll(m)
        <Matrix: rows=
        [ 3,  2,  1,  0]
        [-2,  0,  2,  4]>

    References:
        https://github.com/orisano/olll/blob/master/olll.py
        https://en.wikipedia.org/wiki/Lenstra%E2%80%93Lenstra%E2%80%93Lov%C3%A1sz_lattice_basis_reduction_algorithm
    """
    from samson.math.all import QQ
    Matrix = _mat.Matrix
    DenseVector = _dense.DenseVector


    def vecs_to_matrix(vecs):
        return Matrix([vec.values for vec in vecs])


    # Prepare ring and basis
    if type(in_basis.coeff_ring).__name__ != 'FractionField':
        from samson.math.algebra.fields.fraction_field import FractionField
        R = FractionField(in_basis.coeff_ring)
        in_basis = Matrix([[R(elem) for elem in row] for row in in_basis.rows], coeff_ring=R)

    R     = in_basis.coeff_ring
    basis = deepcopy(in_basis)
    n     = len(basis)
    basis = [DenseVector(row) for row in basis.rows]

    ortho, mu = gram_schmidt(in_basis)


    # Prepare parameters
    half  = R((R.ring.one, R.ring.one*2))
    delta = QQ(delta)
    d_num = int(delta.numerator)
    d_den = int(delta.denominator)


    # Perform LLL
    k = 1
    while k < n:
        for j in reversed(range(k)):
            mu_kj = mu[k, j]

            if abs(mu_kj) > half:
                scalar    = round(mu_kj)
                basis[k] -= basis[j] * scalar
                ortho, mu = gram_schmidt(vecs_to_matrix(basis))


        # Prepare only needed vectors
        # 'o_k' needs to be specially handled since 'gram_schmidt' can remove vectors
        o_k  = ortho[k] if len(ortho) >= k+1 else [R.zero * in_basis.num_cols]
        M_k  = Matrix([o_k])
        M_k1 = Matrix([ortho[k-1]])
        O    = (M_k1 * M_k1.T)[0,0]

        # This should be ring-agnostic
        if (M_k * M_k.T)[0,0] * d_den >= O*d_num - d_den * mu[k, k-1]**2 * O:
            k += 1
        else:
            basis[k], basis[k-1] = deepcopy(basis[k-1]), deepcopy(basis[k])
            ortho, mu = gram_schmidt(vecs_to_matrix(basis))
            k = max(k-1, 1)

    return vecs_to_matrix(basis)


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


def random_int_between(a: int, b :int) -> int:
    """
    Finds a unbiased, uniformly-random integer between `a` and `b`-1 (i.e. "[`a`, `b`)").

    Parameters:
        a (int): Lower bound.
        b (int): Upper bound.
    
    Returns:
        int: Random integer.
    
    Example:
        >>> from samson.math.general import random_int_between
        >>> n = random_int_between(500, 1000)
        >>> n >= 500 and n < 1000
        True

    """
    return a + random_int(b - a)


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
    if start_int < 2:
        return 2

    start_int |= 1
    while not is_prime(start_int):
        start_int += 2

    return start_int



def berlekamp_massey(output_list: list) -> 'Polynomial':
    """
    Performs the Berlekamp-Massey algorithm to find the shortest LFSR for a binary output sequence.

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
        <Polynomial: x**25 + x**17 + x**13 + x**5 + 1, coeff_ring=ZZ/ZZ(2)>

    References:
        https://en.wikipedia.org/wiki/Berlekamp%E2%80%93Massey_algorithm
    """
    Polynomial = _poly.Polynomial
    ZZ = _integer_ring.ZZ

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
    Calculates Euler's totient of `n`. The totient is the number of elements coprime to `n` that are less than `n`.

    Parameters:
        n        (int): Number to find the totient of.
        factors (dict): Factors of `n`.

    Returns:
        int: Totient of `n`.
    """
    if not factors:
        factors = _factor_gen.factor(n)

    t = 1
    for p, e in factors.items():
        t *= (p-1) * p**(e-1)

    return t


def pollards_kangaroo(g: 'RingElement', y: 'RingElement', a: int, b: int, iterations: int=30, f: FunctionType=None, apply_reduction: bool=True) -> int:
    """
    Probabilistically finds the discrete logarithm of base `g` in GF(`p`) of `y` in the interval [`a`, `b`].

    Parameters:
        g        (RingElement): Generator.
        y        (RingElement): Number to find the discrete logarithm of.
        a                (int): Interval start.
        b                (int): Interval end.
        iterations       (int): Number of times to run the outer loop. If `f` is None, it's used in the pseudorandom map.
        f               (func): Pseudorandom map function of signature (`y`: RingElement, k: int) -> int.
        apply_reduction (bool): Whether or not to reduce the answer by the ring's order.
    
    Returns:
        int: The discrete logarithm. Possibly None if it couldn't be found.
    
    Examples:
        >>> from samson.math.general import pollards_kangaroo
        >>> from samson.math.algebra.all import *
        >>> p = find_prime(2048) 
        >>> g, x = 5, random_int_between(1, p)
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
        >>> curve.G * dlog == curve.zero
        True

    References:
        https://en.wikipedia.org/wiki/Pollard%27s_kangaroo_algorithm
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
            f_yT = f(yT, k)
            xT  += f_yT
            yT  += g*f_yT


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



def sieve_of_eratosthenes(n: int, chunk_size: int=1024, prime_base: set=None) -> list:
    """
    Finds all primes up to `n`.
 
    Parameters:
        n          (int): Limit.
        chunk_size (int): Size of internal lists.
        prime_base (set): Initial set of primes to sieve against.

    Returns:
        generator: Generator of prime numbers.

    Examples:
        >>> from samson.math.general import sieve_of_eratosthenes
        >>> list(sieve_of_eratosthenes(100))
        [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]

    """
    n_2 = n // 2
    k   = kth_root(n, 2)

    # Allow preloading, but remove 2 since it's intrinsically removed
    if not prime_base:
        prime_base = PRIMES_UNDER_1000.difference({2})

    # Generate what's in prime_base first
    for p in {2}.union(prime_base):
        if p < n:
            yield p
        else:
            return

    # Chunk the space, but don't redo a chunk the prime_base fully covers
    for chunk in range(len(list(prime_base)) // chunk_size, math.ceil(n_2 / chunk_size)):
        true_idx  = chunk * chunk_size
        true_size = min(n_2 - true_idx, chunk_size)

        # Remove 1
        A = [true_idx != 0] + [True] * (true_size-1)

        # Remove all indices based on prime base
        for p in prime_base:
            for j in range(p - true_idx*2 % (p*2), true_size*2, p*2):
                if j < 0:
                    continue
                A[j//2] = False


        # Mark off multiples of new primes
        # Don't need to if true_idx > k
        if true_idx < k:
            for i in range(2 if not true_idx else 0, true_size, 2):
                true_i = i+true_idx*2+1

                if true_size > (true_i // 2) and A[true_i//2]:
                    for j in range(true_i**2 // 2, true_size, true_i):
                        A[j] = False

        # Add to prime base
        new_primes = {(idx + true_idx)*2+1 for idx, is_prime in enumerate(A) if is_prime}
        for p in new_primes:
            yield p

        prime_base = prime_base.union(new_primes)



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

    for prime in sieve_of_eratosthenes(n.bit_length()*2+1):
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



def find_representative(quotient_element: 'QuotientElement', valid_range: list) -> int:
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



def frobenius_trace_mod_l(curve: object, l: int) -> 'QuotientElement':
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
    ZZ = _integer_ring.ZZ

    torsion_quotient_ring = ZZ/ZZ(l)
    psi = curve.division_poly(l)

    # Build symbolic torsion group
    R = curve.curve_poly_ring
    S = R/psi
    T = Frac(S, simplify=False)
    sym_curve = WeierstrassCurve(a=T([curve.a]), b=curve.b, ring=T, check_singularity=False)

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
    from samson.math.symbols import Symbol
    ZZ = _integer_ring.ZZ

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


def bsgs(g: 'RingElement', h: 'RingElement', end: int, e: 'RingElement'=None, start: int=0) -> int:
    """
    Performs Baby-step Giant-step with an arbitrary finite cyclic group.

    Parameters:
        g  (RingElement): Generator/base.
        h  (RingElement): The result to find the discrete logarithm of.
        end        (int): End of the search range.
        e  (RingElement): Starting point of the aggregator.
        start      (int): Start of the search range.

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
        e = g.ring.zero

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



def pohlig_hellman(g: 'RingElement', h: 'RingElement', n: int=None, factors: dict=None) -> int:
    """
    Computes the discrete logarithm for finite abelian groups with a smooth order.

    Parameters:
        g (RingElement): Generator element.
        h (RingElement): Result to find discrete logarithm of.
        n         (int): Order of the group.
        factors  (dict): `n`'s factorization.

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

    References:
        https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm
    """
    if not n:
        n = g.order

    if not factors:
        factors = _factor_gen.factor(n)

    def pp_bsgs(g, h, p, e):
        x = [0]*(e+1)

        gamma = g*(p**(e-1))
        for k in range(e):
            h_k = (g * -x[k] + h) * (p**(e-1-k))
            d_k = h_k._plog(gamma, p)
            x[k+1] = x[k] + d_k * p**k

        return x[-1]

    x = []
    for p, e in factors.items():
        ex_i = (n // p**e)
        g_i  = g * ex_i
        h_i  = h * ex_i
        x_i  = pp_bsgs(g_i, h_i, p, e)
        x.append(x_i)

    return crt(list(zip(x, [p**e for p, e in  factors.items()])))[0]



def pollards_rho_log(g: 'RingElement', y: 'RingElement', order: int=None) -> int:
    """
    Computes the discrete logarithm using Pollard's Rho.

    Parameters:
        g (RingElement): Generator element.
        y (RingElement): Result to find discrete logarithm of.
        order     (int): Order of the group.

    Returns:
        int: The discrete logarithm of `y` given `g`.

    References:
        http://koclab.cs.ucsb.edu/teaching/ecc/project/2015Projects/Blumenfeld-Presentation.pdf
        https://math.mit.edu/classes/18.783/2017/LectureNotes10.pdf
    """
    ZZ = _integer_ring.ZZ

    def xab(x, a, b, g, y):
        sub = hash(x) % 3

        if sub == 0:
            x = x + x
            a = a * 2
            b = b * 2
        elif sub == 1:
            x = x + g
            a = a + 1
        else:
            x = x + y
            b = b + 1

        return x, a, b


    residues = []
    n        = order or g.order
    Z        = ZZ/ZZ(n)

    # Main loop
    while True:
        a       = Z.random()
        x, b    = g*int(a), Z.zero
        X, A, B = x, a, b


        for _ in range(n):
            x, a, b = xab(x, a, b, g, y)

            X, A, B = xab(X, A, B, g, y)
            X, A, B = xab(X, A, B, g, y)

            if x == X:
                break

        r   = B-b
        if not r:
            continue

        # Note we might've found just a factor of the order
        P   = ZZ/ZZ(r.order)
        res = P(a-A)/P(r)

        residues.append(P(res))
        res, _ = crt(residues)

        if int(res)*g == y:
            return int(res)



def miller_rabin(n: int, k: int=64, bases: list=None) -> bool:
    """
    Probabilistic primality test. Each iteration has a 1/4 false positive rate.

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

    References:
        https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test#Miller%E2%80%93Rabin_test
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
                yield random_int_between(2, n_1)

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


_FB_LARGE_MOD = 3989930175
def is_square(n: int, heuristic_only: bool=False) -> bool:
    """
    Determines if `n` is a square using "fenderbender" tests first.

    Parameters:
        n               (int): Number to test.
        heuristic_only (bool): Whether or not to only use heuristic tests and not validate.

    Returns:
        bool: Whether or not `n` is a square.

    Examples:
        >>> from samson.math.general import is_square
        >>> p = 18431211066281663581
        >>> is_square(p**2)
        True

        >>> is_square(6)
        False

    References:
        https://mersenneforum.org/showpost.php?p=110896
    """
    if n in [0, 1]:
        return True

    m = n % 128
    if ((m*0x8bc40d7d) & (m*0xa1e2f5d1) & 0x14020a):
        return False

    n_mod = n % _FB_LARGE_MOD

    m = n_mod % 63
    if ((m*0x3d491df7) & (m*0xc824a9f9) & 0x10f14008):
        return False

    m = n_mod % 25
    if ((m*0x1929fc1b) & (m*0x4c9ea3b2) & 0x51001005):
         return False

    if heuristic_only:
        return n % 10 not in {2,3,7,8}

    return kth_root(n, 2)**2 == n


def jacobi_symbol(n: int, k: int) -> ResidueSymbol:
    """
    Generalization of the Legendre symbol.

    Parameters:
        n (int): Possible quadatric residue.
        k (int): Modulus (must be odd).

    Returns:
        ResidueSymbol: Jacobi symbol.
    
    Examples:
        >>> from samson.math.general import jacobi_symbol
        >>> jacobi_symbol(4, 7)
        <ResidueSymbol.EXISTS: 1>

        >>> jacobi_symbol(5, 7)
        <ResidueSymbol.DOES_NOT_EXIST: -1>

    References:
        https://en.wikipedia.org/wiki/Jacobi_symbol
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

    References:
        https://docs.sympy.org/latest/_modules/sympy/ntheory/primetest.html#isprime
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

    References:
        https://en.wikipedia.org/wiki/Baillie%E2%80%93PSW_primality_test
    """
    if n < 0:
        return False

    if n in PRIMES_UNDER_1000:
        return True

    for prime in PRIMES_UNDER_1000:
        if (n % prime) == 0:
            return False

    return miller_rabin(n, bases=[2]) and is_strong_lucas_pseudoprime(n)


def is_primitive_root(a: int, p: int) -> bool:
    """
    Returns whether or not `a` is a primitive root in ZZ/ZZ(p)*.
    `a` is a primitive root of `p` if `a` is the smallest integer such that `a`'s order is the order of the ring.

    Parameters:
        a (int): Possible primitive root.
        p (int): Modulus.
    
    Returns:
        bool: Whether or not `a` is a primitive root.
    
    Examples:
        >>> from samson.math.general import is_primitive_root
        >>> is_primitive_root(3, 10)
        True

        >>> is_primitive_root(9, 10)
        False

        >>> is_primitive_root(45, 2)
        True

        >>> is_primitive_root(208, 3)
        False

        >>> is_primitive_root(120, 173)
        True

    """
    ZZ = _integer_ring.ZZ

    Z_star = (ZZ/ZZ(p)).mul_group()
    a_star = Z_star(a)

    return gcd(a, p) == 1 and a_star*Z_star.order == Z_star.one and a_star.order == Z_star.order



def product(elem_list: list, return_tree=False) -> object:
    """
    Calculates the product of all elements in `elem_list`.

    Parameters:
        elem_list   (list): List of RingElements.
        return_tree (bool): Whether or not to return the intermediate tree results.
    
    Returns:
        RingElement: Product of all RingElements.
    
    Examples:
        >>> from samson.math.general import product
        >>> from samson.math.all import ZZ
        >>> product([ZZ(1), ZZ(2), ZZ(3)])
        <IntegerElement: val=6, ring=ZZ>

        >>> product([ZZ(1), ZZ(2), ZZ(3)], True)
        [[<IntegerElement: val=1, ring=ZZ>, <IntegerElement: val=2, ring=ZZ>, <IntegerElement: val=3, ring=ZZ>, <IntegerElement: val=1, ring=ZZ>], [<IntegerElement: val=2, ring=ZZ>, <IntegerElement: val=3, ring=ZZ>], [<IntegerElement: val=6, ring=ZZ>]]

    References:
        https://facthacks.cr.yp.to/product.html
    """
    X = list(elem_list)
    if len(X) == 0: return 1
    X_type = type(X[0])

    tree = [X]
    one  = 1 if X_type is int else X[0].ring.one

    while len(X) > 1:
        if len(X) % 2:
            X.append(one)

        X = [X_type.__mul__(*X[i*2:(i+1)*2]) for i in range(len(X) // 2)]

        if return_tree:
            tree.append(X)

    return tree if return_tree else X[0]



def batch_gcd(elem_list: list) -> list:
    """
    Calculates the greatest common denominators of any two elements in `elem_list`.

    Parameters:
        elem_list (list): List of RingElements.
    
    Returns:
        list: Greatest common denominators of any two elements.
    
    Examples:
        >>> from samson.math.general import batch_gcd
        >>> batch_gcd([1909, 2923, 291, 205, 989, 62, 451, 1943, 1079, 2419])
        [1909, 1, 1, 41, 23, 1, 41, 1, 83, 41]

    References:
        https://facthacks.cr.yp.to/batchgcd.html
    """
    prods = product(elem_list, True)
    R = prods.pop()
    while prods:
        elem_list = prods.pop()
        R         = [R[i // 2] % elem_list[i]**2 for i in range(len(elem_list))]

    return [gcd(r // n, n) for r, n in zip(R, elem_list)]



def smoothness(n: int, factors: dict=None, **factor_kwargs) -> float:
    """
    Calculates the smoothness of an integer `n` as a ratio of the number of non-trivial factors to the number of bits.
    Thus, primes are 0% smooth and 2**n is 100% smooth.

    Parameters:
        n        (int): Integer to analyze.
        factors (dict): Factors of `n`.

    Returns:
        float: Smoothness ratio.

    Examples:
        >>> from samson.math.general import smoothness, is_prime
        >>> p = 211
        >>> assert is_prime(p)
        >>> smoothness(p)
        0.0

        >>> smoothness(p-1)
        0.5185212203629948

    """
    if not factors:
        if not factor_kwargs:
            factor_kwargs = {"use_rho": False}

        factors = _factor_gen.factor(n, **factor_kwargs)

    # 'factors' will return {n: 1} if `n` is prime
    # Just early-out since there will be zero non-trivials anyway
    if n in factors:
        return 0.0

    return (sum(factors.values())) / math.log(n, 2)



def is_safe_prime(p: int) -> bool:
    """
    Determines if `p` is a safe prime.

    Parameters:
        p (int): Prime to analyze.
    
    Returns:
        bool: Whether `p` is a safe prime.
    
    Examples:
        >>> from samson.math.general import is_safe_prime
        >>> from samson.protocols.diffie_hellman import DiffieHellman
        >>> is_safe_prime(DiffieHellman.MODP_2048)
        True

    """
    q, r = divmod(p-1, 2)
    return not r and is_prime(q) and is_prime(p)


def is_sophie_germain_prime(p: int) -> bool:
    """
    Determines if `p` is a Sophie Germain prime.

    Parameters:
        p (int): Prime to analyze.
    
    Returns:
        bool: Whether `p` is a Sophie Germain prime.
    
    Examples:
        >>> from samson.math.general import is_sophie_germain_prime
        >>> from samson.protocols.diffie_hellman import DiffieHellman
        >>> is_sophie_germain_prime((DiffieHellman.MODP_2048-1)//2)
        True

    """
    return is_prime(2*p+1)


def is_carmichael_number(n: int, factors: dict=None) -> bool:
    """
    Determines if `n` is a Carmichael number. A Carmichael number is a composite number that
    passes the Fermat primality test for all bases coprime to it.

    Parameters:
        n        (int): Integer.
        factors (dict): Factors of `n`.
    
    Returns:
        bool: Whether or not `n` is a Carmichael number.

    References:
        https://en.wikipedia.org/wiki/Carmichael_number#Korselt's_criterion
    """
    factors = factors or _factor_gen.factor(n, reraise_interrupt=True)


    if max(factors.values()) > 1 or len(factors) == 1:
        return False

    return not any((n-1) % (p-1) for p in factors)



def find_carmichael_number(min_bits: int=None, k: int=None) -> int:
    """
    Finds a Carmichael number with a size of `min_bits` or initialized with `k`.

    Parameters:
        min_bits (int): Minimum size of number to find.
        k        (int): Looping multiplier.

    References:
        https://en.wikipedia.org/wiki/Carmichael_number#Discovery
    """
    if min_bits:
        # Take into account `k` three times and 6*12*18 is 11 bits
        k = 2**((min_bits-11)//3)

    while True:
        a = 6*k+1
        b = 12*k+1
        c = 18*k+1

        if all(is_prime(elem) for elem in [a, b, c]):
            return a*b*c, (a, b, c)

        k += 1



def carmichael_function(n: int, factors: dict=None) -> int:
    """
    Finds the smallest positive integer `m` such that `a^m = 1 (mod n)`.

    Parameters:
        n        (int): Modulus.
        factors (dict): Factors of `n`.

    Returns:
        int: The least universal exponent.

    References:
        https://en.wikipedia.org/wiki/Carmichael_function
    """
    if not factors:
        factors = _factor_gen.factor(n)

    result = 1
    for p, e in factors.items():
        a = totient(0, {p: e})
        if p == 2 and e > 2:
            a //= 2

        result = lcm(result, a)

    return result


def coppersmiths(N: int, f: 'Polynomial', beta: float=1, epsilon: float=None, X: int=None, m: int=None, t: int=None) -> list:
    """
    Finds small roots of a polynomial in `ZZ`/`ZZ`(`N`) using Coppersmith's method.

    Parameters:
        N         (int): Modulus.
        f  (Polynomial): Polynomial to find roots of.
        beta    (float): Tweaks the size of the roots we look for in the polynomial. (Roots mod `b`, where `b` > `N`^`beta`)
        epsilon (float): Tweaks the size of the matrix.
        X         (int): Absolute bound for roots.
        m         (int): Tweaks number of columns.
        t         (int): Tweaks number of rows.

    Returns:
        list: List of small roots in Zn[x].

    References:
        https://github.com/sagemath/sage/blob/develop/src/sage/rings/polynomial/polynomial_modn_dense_ntl.pyx#L401
        "Finding Small Solutions to Small Degree Polynomials" (http://cr.yp.to/bib/2001/coppersmith.pdf)
    """
    ZZ = _integer_ring.ZZ
    Matrix = _mat.Matrix

    d = f.degree()
    x = f.symbol

    if not epsilon:
        epsilon = beta/8


    m = m or math.ceil(max(beta**2/(d*epsilon), 7*beta/d))
    t = t or int(d*m * (1/beta - 1))

    if not X:
        X = math.ceil(0.5 * N**(beta**2/d - epsilon))

    g = [x**j * N**(m-i) * f**i for i in range(m) for j in range(d)]
    g.extend([x**i * f**m for i in range(t)])

    # Build the problem matrix
    B = Matrix.fill(ZZ.zero, len(g), d*m + max(d, t))
    for i in range(len(g)):
        for j in range(g[i].degree()+1):
            B[i,j] = (g[i].coeffs[j]*X**j)


    # Solve the problem matrix
    B = Matrix(B, ZZ).LLL()
    k = sum([x**i*ZZ(B[0, i] // X**i) for i in range(B.num_cols)])

    R     = k.roots()
    Zn    = ZZ/ZZ(N)
    roots = set(Zn(r) for r in R if abs(r) <= X)
    Nb    = N**beta
    return [root for root in roots if gcd(N, root) >= Nb]



def prime_number_theorem(n: int) -> int:
    """
    Approximates the number of primes less than `n`.

    Parameters:
        n (int): Maximum bound.
    
    Returns:
        int: Approximate number of primes less than `n`.
    
    References:
        https://en.wikipedia.org/wiki/Prime_number_theorem
    """
    return n // math.floor(math.log(n))


pnt = prime_number_theorem



def index_calculus(g: 'MultiplicativeGroupElement', y: 'MultiplicativeGroupElement', order: int=None) -> int:
    """
    Computes the discrete logarithm of `y` to base `g`

    Parameters:
        g (MultiplicativeGroupElement): Generator.
        y (MultiplicativeGroupElement): Target of form `g`^`x`.
        order                    (int): Order of `g`.

    Returns:
        int: The discrete logarithm of `y`.

    Examples:
        >>> from samson.all import ZZ, index_calculus
        >>> p, q, g, d, y = 3272514023, 1636257011, 2, 1390585808, 1244484161
        >>> R = (ZZ/ZZ(p)).mul_group()
        >>> index_calculus(R(g), R(y))
        1390585808

    References:
        https://github.com/Gr1zz/dlog/blob/master/index_calculus.sage
        http://moais.imag.fr/membres/jean-louis.roch/perso_html/transfert/2009-06-19-IntensiveProjects-M1-SCCI-Reports/AlnuaimiKhuloud.pdf
    """
    from math import exp, sqrt, log, ceil
    ZZ = _integer_ring.ZZ
    Matrix = _mat.Matrix
    trial_division = _factor_gen.trial_division

    def is_smooth_trial(n, B):
        facs = trial_division(n, prime_base=B)
        return facs.recombine() == n, facs


    Fp = g.ring.ring
    Fq = ZZ/ZZ(order or g.order)

    g = g.cache_mul(Fq.order.bit_length())
    y = y.cache_mul(Fq.order.bit_length())

    if not is_prime(Fq.order):
        raise ValueError('Index calculus requires a prime group')

    p    = Fp.order
    B    = ceil(exp(0.5*sqrt(2*log(p)*log(log(p)))))
    base = list(sieve_of_eratosthenes(B+1))

    # Precompute indices
    indices   = {p:i for i,p in enumerate(base)}
    S         = len(base)
    relations = Matrix.fill(Fq.zero, S+1, S)


    # Find smooth relations
    row = []
    k   = 0
    while (k < S+1):
        while True:
            a = Fq.random()
            b = Fq.random()
            if not (a,b) in row:
                break


        z = g*int(a)+y*int(b)

        is_smooth, facs = is_smooth_trial(int(z), base)
        if is_smooth:
            row.append((a,b))

            for p_i, e_i in facs.items():
                i = indices[p_i]
                relations[k, i] = Fq(e_i)

            k += 1

    # Solve
    ker  = relations.left_kernel()[0]
    A, B = 0, 0

    for ker_i, row_i in zip(ker, row):
        A += ker_i*row_i[0]
        B += ker_i*row_i[1]

    return int(-A * ~Fq(B))


def estimate_L_complexity(a, c, n):
    import math
    return math.e**(c*math.log(n)**a * (math.log(math.log(n)))**(1-a))



def log(y: 'RingElement', base: 'RingElement') -> int:
    """
    Computes the logarithm of `y` to `base`.

    Parameters:
        base (RingElement): Base.
    
    Returns:
        int: `x` such that `base`^`x` == `y`.
    """
    if type(y) in [int, float]:
        return math.log(y, base)
    else:
        return y.log(base)
