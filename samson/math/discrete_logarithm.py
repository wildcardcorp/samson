from samson.auxiliary.complexity import add_complexity, KnownComplexities
from samson.utilities.exceptions import SearchspaceExhaustedException
from samson.math.general import is_prime, _integer_ring, _factor_gen, _mat, sieve_of_eratosthenes, kth_root, crt
from samson.utilities.general import binary_search_list
from samson.utilities.runtime import RUNTIME
from typing import Tuple
import math

@add_complexity(KnownComplexities.IC)
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


    Fq = ZZ/ZZ(order or g.order())
    q  = Fq.order()
    p  = g.ring.characteristic()

    g = g.cache_mul(q.bit_length())
    y = y.cache_mul(q.bit_length())

    if not is_prime(q):
        raise ValueError('Index calculus requires a prime group')

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



@RUNTIME.global_cache(8)
def __build_bsgs_table(g: 'RingElement', end: int, e: 'RingElement'=None, start: int=0) -> Tuple[int, dict]:
    search_range = end - start
    table        = {}
    m            = kth_root(search_range, 2)

    if not e:
        e = g.ring.zero

    for i in range(m):
        table[e] = i
        e += g
    
    return m, table



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
    if hasattr(h, 'bsgs'):
        try:
            return h.bsgs(g, end=end, start=start, e=e)
        except (ValueError, SearchspaceExhaustedException):
            # Implementation specific BSGS may not handle all situations
            pass

    m, table = __build_bsgs_table(g, end, e, start)

    factor = g * m
    o = g * start
    e = h
    for i in range(m):
        e = h - o
        if e in table:
            return i*m + table[e] + start

        o += factor

    raise SearchspaceExhaustedException("This shouldn't happen; check your arguments")


@add_complexity(KnownComplexities.PH)
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
        >>> pohlig_hellman(curve.G, h, curve.G.order())
        28

    References:
        https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm
    """
    if not n:
        n = g.order()

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


@add_complexity(KnownComplexities.PH)
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
    n        = order or g.order()
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

        r = B-b
        if not r:
            continue

        # Note we might've found just a factor of the order
        P   = ZZ/ZZ(r.order())
        res = P(a-A)/P(r)

        residues.append(P(res))
        res, _ = crt(residues)

        if int(res)*g == y:
            return int(res)
        else:
            Z  = ZZ/ZZ(n // r.order())
            g *= r.order()
            y *= r.order()



_CADO_DLOG_CACHE = {}

def _cado_nfs_dlog(y: int, q: int, p: int) -> 'Factors':
    # https://stackoverflow.com/a/27661481
    import subprocess

    if not (is_prime(p) and is_prime(q)):
        raise RuntimeError(f'{p} and {q} must be prime.')

    if not RUNTIME.cado_nfs_loc:
        raise RuntimeError("cado-nfs not in PATH; you must manually set 'RUNTIME.cado_nfs_loc'")


    if (q, p) in _CADO_DLOG_CACHE:
        snapshot = _CADO_DLOG_CACHE[(q, p)]
        z_log_b = subprocess.check_output([RUNTIME.cado_nfs_loc, snapshot.decode(), f'target={y}'], stderr=subprocess.DEVNULL)
        return int(z_log_b.strip())
    else:
        pipes = subprocess.Popen([RUNTIME.cado_nfs_loc, '-dlp', '-ell', str(q), f'target={y}', str(p)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        std_out, std_err = pipes.communicate()


        if pipes.returncode:
            err_msg = f"{std_err.strip()}. Code: {pipes.returncode}"
            raise RuntimeError(err_msg)


        snapshot = std_err.split(b':root: If you want to compute a new target, run ')[1].split(b' ')[1]

        _CADO_DLOG_CACHE[(q, p)] = snapshot
        return int(std_out.strip())


def cado_nfs_dlog(g: int, y: int, q: int, p: int) -> 'Factors':
    # https://stackoverflow.com/a/27661481
    ZZ = _integer_ring.ZZ
    g_log = _cado_nfs_dlog(g, q, p)
    y_log = _cado_nfs_dlog(y, q, p)

    W = ZZ/ZZ(q)
    return int(W(y_log)/W(g_log))
