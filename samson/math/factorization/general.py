from samson.math.factorization.factors import Factors
from samson.utilities.exceptions import NotInvertibleException, ProbabilisticFailureException
from types import FunctionType
from tqdm import tqdm
import math

from samson.auxiliary.lazy_loader import LazyLoader
integer_ring = LazyLoader('integer_ring', globals(), 'samson.math.algebra.rings.integer_ring')
poly         = LazyLoader('poly', globals(), 'samson.math.polynomial')
samson_math  = LazyLoader('samson_math', globals(), 'samson.math.general')
siqs         = LazyLoader('siqs', globals(), 'samson.math.factorization.siqs')


def pollards_p_1(n: int, B1: int=None, B2: int=None, a: int=2, E: int=1, exclude_list: list=None) -> int:
    """
    Factoring algorithm that exploits the smoothness of `p-1` for factors `p_0..p_k` of `n`.
    This is due to the multiplicative group structure, cyclic properties of Z mod `n`, and Fermat's little theorem.

    Parameters:
        n  (int): Integer to factor.
        B1 (int): Lower bound. Will automatically increase.
        B2 (int): Maximum bound.
        a  (int): Starting base of `a^E-1`.
        E  (int): Starting exponent of `a^E-1`.

    Returns:
        int: Factor of `n` or None on failure.

    References:
        https://en.wikipedia.org/wiki/Pollard%27s_p_%E2%88%92_1_algorithm
    """
    kth_root = samson_math.kth_root
    sieve_of_eratosthenes = samson_math.sieve_of_eratosthenes
    gcd = samson_math.gcd

    # Set bounds
    if not B1:
        B1 = max(kth_root(n, 20), 2)

    if not B2:
        # The idea is that we want to target a factor `f < n^(1/5)`
        # whose greatest factor `d < f^(1/3)`.
        B2 = max(kth_root(n, 15), B1**5)


    if not exclude_list:
        exclude_list = []


    for p in sieve_of_eratosthenes(B2):
        if p > B1:
            # By saving a's congruence and resetting E,
            # we can prevent recomputing the entire exponent
            a = pow(a, E, n)
            g = gcd(a-1, n)

            if g == 1:
                B1 *= 2

            elif g == n:
                B1 //= 3
                if not B1:
                    return

            # We found one!
            else:
                return g

            E = 1

        if p not in exclude_list:
            E *= p**int(math.log(n, p))



def _mersenne_p_1(n: int, k: int, B1: int=None, B2: int=None, exclude_list: list=None) -> int:
    # All factors of Mersenne numbers are `1 mod 2` and `1 mod k`
    return pollards_p_1(n=n, B1=B1, B2=B2, a=3, E=2*k, exclude_list=exclude_list or [k])



def _mersenne_fac_subroutine(n: int, p: int):
    is_prime = samson_math.is_prime

    # We only set `fac` to 4 to pass the first "while" condition
    fac        = 4
    e_facs     = Factors()
    reraise_interrupt = False

    try:
        if p in _P2K_FACS:
            cached = _P2K_FACS[p]
            if not n % cached:
                e_facs.add(cached, 1)
                n //= cached

        # Start with fast smoothness factoring
        while fac and n > 1 and not is_prime(n):
            fac = _mersenne_p_1(n, p, B1=2, B2=min(1000000, samson_math.kth_root(n, 2)))
            if fac:
                n //= fac
                e_facs += factor(fac)

        if n > 1:
            left_overs = factor(n, use_trial=False, perfect_power_checks=False, mersenne_check=False, reraise_interrupt=True)
        else:
            left_overs = Factors()

    # This is kinda sloppy, but we need to ferry the interrupt up the chain
    except KeyboardInterrupt:
        reraise_interrupt = True
        left_overs = Factors({n: 1})

    return e_facs + left_overs, reraise_interrupt



def _mersenne_factor(k: Factors, progress_update: FunctionType) -> Factors:
    """
    Internal function.

    This function factors Mersenne numbers by recursively factoring their greatest divisor.
    Here is an example of how it works:
        M12 = M6 * x_1
        M6  = M3 * x_2

    Now we factor M3, x_2, and x_1. We then return the summation of their factorization (e.g. {2: 1} + {3: 1} == {2: 1, 3: 1})
    """
    is_prime = samson_math.is_prime

    k_rec = k.recombine()
    if is_prime(k_rec):
        facs, reraise_interrupt =_mersenne_fac_subroutine(2**k_rec-1, k_rec)
        progress_update(facs.recombine())
        return facs, reraise_interrupt

    else:
        biggest_d = k // list(k)[0]
        d_facs, reraise_interrupt = _mersenne_factor(biggest_d, progress_update)
        left_over = (2**k_rec-1) // (2**biggest_d.recombine()-1)

        # Handle d_fac interrupt
        if reraise_interrupt:
            return d_facs + Factors({left_over: 1}), reraise_interrupt

        k_facs, reraise_interrupt = _mersenne_fac_subroutine(left_over, k_rec)

        # Update prog
        progress_update(k_facs.recombine())
        return k_facs + d_facs, reraise_interrupt



_P2K_FACS = {2: 3, 3: 7, 5: 31, 7: 127, 11: 23, 13: 8191, 17: 131071, 19: 524287, 23: 47, 29: 233, 31: 2147483647, 37: 223, 41: 13367, 43: 431, 47: 2351, 53: 6361, 59: 179951, 61: 2305843009213693951, 67: 193707721, 71: 228479, 73: 439, 79: 2687, 83: 167, 89: 618970019642690137449562111, 97: 11447, 101: 7432339208719, 103: 2550183799, 107: 162259276829213363391578010288127, 109: 745988807, 113: 3391, 127: 170141183460469231731687303715884105727, 131: 263, 137: 32032215596496435569, 139: 5625767248687, 149: 86656268566282183151, 151: 18121, 157: 852133201, 163: 150287, 167: 2349023, 173: 730753, 179: 359, 181: 43441, 191: 383, 193: 13821503, 197: 7487, 199: 164504919713, 211: 15193, 223: 18287, 227: 26986333437777017, 229: 1504073, 233: 1399, 239: 479, 241: 22000409, 251: 503, 257: 535006138814359, 263: 23671, 269: 13822297, 271: 15242475217, 277: 1121297, 281: 80929, 283: 9623, 293: 40122362455616221971122353, 307: 14608903, 311: 5344847, 313: 10960009, 317: 9511, 331: 16937389168607, 337: 18199, 347: 14143189112952632419639, 349: 1779973928671, 353: 931921, 359: 719, 367: 12479, 373: 25569151, 379: 180818808679, 383: 1440847, 389: 56478911, 397: 2383, 401: 856971565399, 409: 4480666067023, 419: 839, 421: 614002928307599, 431: 863, 433: 22086765417396827057, 439: 104110607, 443: 887, 449: 1256303, 457: 150327409, 461: 2767, 463: 11113, 467: 121606801, 479: 33385343, 487: 4871, 491: 983, 499: 20959, 503: 3213684984979279, 509: 12619129, 521: 6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151, 523: 160188778313202118610543685368878688932828701136501444932217468039063, 541: 4312790327, 547: 5471, 557: 3343, 563: 2815747080256641401887817, 569: 15854617, 571: 5711, 577: 3463, 587: 554129, 593: 104369, 599: 16659379034607403556537, 601: 3607, 607: 531137992816767098689588206552468627329593117727031923199444138200403559860852242739162502265229285668889329486246501015346579337652707239409519978766587351943831270835393219031728127, 613: 44599476833089207, 617: 59233, 619: 110183, 631: 333628015107245479, 641: 35897, 643: 3189281, 647: 303303806129303896428103, 653: 78557207, 659: 1319, 661: 1330270433, 673: 581163767, 677: 1943118631, 683: 1367, 691: 906642603313, 701: 796337, 709: 216868921, 719: 1439, 727: 17606291711815434037934881872331611670777491166445300472749449436575622328171096762265466521858927, 733: 694653525743, 739: 184603056517613273120809, 743: 1487, 751: 227640245125324450927745881868402667694620457976381782672549806487, 757: 9815263, 761: 4567, 769: 1591805393, 773: 6864241, 787: 9951597611230279, 797: 2006858753, 809: 4148386731260605647525186547488842396461625774241327567978137, 811: 326023, 821: 419273207, 823: 1460915248436556406607, 827: 66161, 829: 72953, 839: 26849, 853: 2065711807, 857: 6857, 859: 7215601, 863: 8258911, 877: 35081, 881: 26431, 883: 8831, 887: 16173559, 907: 1170031, 911: 1823, 919: 33554520197234177, 929: 13007, 937: 28111, 941: 7529, 947: 295130657, 953: 343081, 967: 23209, 971: 23917104973173909566916321016011885041962486321502513, 977: 867577, 983: 1808226257914551209964473260866417929207023, 991: 8218291649, 997: 167560816514084819488737767976263150405095191554732902607, 1009: 3454817, 1013: 6079, 1019: 2039, 1021: 40841, 1031: 2063, 1033: 196271, 1039: 5080711, 1049: 33569, 1051: 3575503, 1061: 46817226351072265620777670675006972301618979214252832875068976303839400413682313921168154465151768472420980044715745858522803980473207943564433, 1063: 1485761479, 1069: 17481727674576239, 1087: 10722169, 1091: 87281, 1093: 43721, 1097: 980719, 1103: 2207, 1109: 30963501968569, 1117: 53617, 1123: 777288435261989969, 1129: 33871, 1151: 284278475807, 1153: 267497, 1163: 848181715001, 1171: 153606920351, 1181: 4742897, 1187: 256393, 1193: 121687, 1201: 57649, 1213: 327511, 1217: 1045741327, 1223: 2447, 1229: 36871, 1231: 531793, 1237: 2538207129840687799335203259492870476186248896616401346500027311795983, 1249: 97423, 1259: 875965965904153, 1279: 10407932194664399081925240327364085538615262247266704805319112350403608059673360298012239441732324184842421613954281007791383566248323464908139906605677320762924129509389220345773183349661583550472959420547689811211693677147548478866962501384438260291732348885311160828538416585028255604666224831890918801847068222203140521026698435488732958028878050869736186900714720710555703168729087, 1283: 4824675346114250541198242904214396192319, 1289: 15856636079, 1291: 998943080897, 1297: 12097392013313}
def pk_1_smallest_divisor(prime_power: int) -> int:
    """
    Given a prime power, finds the smallest divisor of `prime_power-1`. This function is used to find the size of the smallest subgroup of the multiplicative group of a finite field.

    WARNING: If the base is 2 and the power is a prime > 1259 or a composite > 1585081, this function may become VERY slow
    and probablistic.

    Parameters:
        prime_power (int): Prime power to find factor of (i.e. `p^k`).

    Returns:
        int: Smallest factor of `p^k-1`.

    Analysis:
        `prime_power` is of the form `p^k` where `p` is prime. If `p` is odd, this function immediately
        returns the correct answer (i.e. 2). Otherwise, `p` is 2. If `k`'s smallest factor is <= 1259,
        this function immediately returns a cached answer. From here, we need to perform factoring.
        We don't necessarily need to fully factor `k`, just find its smallest factor. Since we break on
        the first factor found, its probable but not guaranteed that the found factor `d` is the smallest.
        If `k` is a semiprime, then we have to fully factor it, and thus `d` is the smallest. Assuming
        `d` is indeed the smallest, if `d` is a Sophie Germain prime and congruent to 3 mod 4, we use
        a theorem's result to prove that `2d+1` is a factor. Since another theorem about Mersenne
        numbers states that for a number `2^p-1` every factor is of the form `2px+1` for some `x`,
        we can show that `2d+1` is minimal since `x` must be one. If `d` is not a Sophie Germain
        prime, we have to factor `2^d-1`. Again, we break on the first factor found.

        For odd `p`, this function is O(1).
        For `p == 2`:
            If `k` <= 1259 -> O(1)
            If `k` is a Sophie Germain prime -> O(1)
            For the minimal prime `d` such that `d|k`:
                If `d` <= 1259 -> O(1) (92.17% chance assuming uniform distribution of `k`)
                If `d` is a Sophie Germain prime -> O(d^2) (time complexity of Pollard's rho of `k`)
                For the minimal prime `e` such that `e|2^d-1` -> O(e^2) (time complexity of Pollard's rho of `2^d-1`)

        The smallest factor cache for Mersenne numbers includes every prime up to 1259
        (actually up to 1297, but we're missing M1277).
        92.17% of all integers are divisible by these primes.

        This is calcuated like so:
        `percentage = 1-(totient(n)/n)`

        Where `n` is the product of the cached primes.

    References:
        https://homes.cerias.purdue.edu/~ssw/cun/pmain420.txt
        https://en.wikipedia.org/wiki/Mersenne_prime#Theorems_about_Mersenne_numbers
    """
    is_prime = samson_math.is_prime

    # This works for all odd prime powers
    if not (prime_power-1) % 2:
        return 2

    # `p` must be be 2
    k = int(math.log(prime_power, 2))

    # Constant time
    if k in _P2K_FACS:
        return _P2K_FACS[k]

    # Works for all composites up to 1,585,081 (1259^2)
    for p in _P2K_FACS:
        if not k % p:
            return _P2K_FACS[p]


    # If we're here, `k` is either:
    # 1) A composite larger than 1585081 with no factors less than or equal to 1259
    # 2) A prime number greater than 1259

    # Firstly, we know that if `d` is the smallest divisor of `k`, then `2^d-1` contains
    # the smallest divisor of `2^k-1`. If `k` is a prime power, its base is greater than
    # 1259. If `k` is a composite power, all of its factors are greater than 1259.
    # Since we've already checked if `k` is divisible by primes through 1259, there's no point
    # in using trial division. We will, however, check if it's a perfect power. Once we've found its
    # smallest factor `d`, we know `d` is prime, and `2^d-1` isn't a perfect power. We also know we can
    # skip trial division for `2^d-1` since every factor of `2^p-1` for prime `p` has unique factors.
    # The biggest compromise we're making is immediately stopping on the first factor found. While
    # finding the smallest factor first is more probable, neither Pollard's rho nor ECM guarantee it.
    find_one = lambda n, facs: len(facs)
    d = list(factor(k, use_trial=False, user_stop_func=find_one))[0]

    # If `d` is a Sophie Germain prime and congruent to 3 mod 4, `2d+1` is a factor.
    if d % 4 == 3 and is_prime(2*d+1):
        return 2*d+1

    return list(factor(2**d-1, use_trial=False, perfect_power_checks=False, user_stop_func=find_one))[0]



def is_perfect_power(n: int) -> (bool, int, int):
    """
    Determines if `n` is a perfect power. If it is, the root and exponent are returned.

    Parameters:
        n (int): Possible perfect power.
    
    Returns:
        (bool, int, int): Formatted as (is_prime_power, root, exponent).
    
    Examples:
        >>> from samson.math.factorization.general import is_perfect_power
        >>> p = 322061084716023110461357635858544836091
        >>> is_perfect_power(p**17)
        (True, 322061084716023110461357635858544836091, 17)

    References:
        https://mathoverflow.net/a/106316
    """
    kth_root =samson_math.kth_root
    is_power_of_two = samson_math.is_power_of_two
    is_prime = samson_math.next_prime
    next_prime = samson_math.next_prime

    if is_power_of_two(n):
        return True, 2, int(math.log(n, 2))

    e = 1
    last_root = n

    p = 2
    while True:
        is_root = True

        # Keep trying to remove `p` roots out
        while is_root:
            root    = kth_root(last_root, p)
            is_root = root**p == last_root

            if is_root:
                if is_prime(root):
                    e = e*p
                    return e > 1, root, e
                else:
                    last_root = root
                    e         *= p

            elif root > 2:
                # Make sure we don't overflow Python
                if root.bit_length() < 1024:
                    # We can calculate the minimum root that produces the next base
                    # Imagine the following: n = 3**2113, p = 2003, root = 4
                    # The next prime is 2011, but 'samson_math.kth_root(n, 2011)' is also 4.
                    # Thus, we've tried nothing new. The following calculations
                    # allow us to skip redudant primes
                    next_base = math.ceil(int(math.log(last_root, root-1)))
                    p = max(next_prime(next_base), next_prime(p+1))
                else:
                    p = next_prime(p+1)

            else:
                return e > 1, last_root, e



def trial_division(n: int, limit: int=1000, prime_base: list=None, progress_update: FunctionType=lambda n: None):
    sieve_of_eratosthenes = samson_math.sieve_of_eratosthenes

    facs = Factors()

    if n < 0:
        n //= -1
        facs.add(-1)

    for prime in (prime_base or samson_math.sieve_of_eratosthenes(limit)):
        if n == 1:
            break

        while not n % prime:
            facs.add(prime)
            progress_update(prime)
            n //= prime
    
    return facs


def pollards_rho(n: int, max_attempts: int=None) -> int:
    """
    Uses Pollard's rho to find a factor of `n`.

    Parameters:
        n (int): Integer to factor.
    
    Returns:
        int: Factor of `n`.
    
    Examples:
        >>> from samson.math.factorization.general import pollards_rho
        >>> pollards_rho(26515460203326943826)
        2

    References:
        https://en.wikipedia.org/wiki/Pollard%27s_rho_algorithm
        https://github.com/skollmann/PyFactorise/blob/master/factorise.py
        "An improved Monte Carlo factorization algorithm" (https://maths-people.anu.edu.au/~brent/pd/rpb051i.pdf)
    """
    gcd = samson_math.gcd

    y, c, m  = [samson_math.random_int_between(1, n-1) for _ in range(3)]
    r, q, g  = 1, 1, 1
    attempts = 0

    brent = lambda c, n, x: (x*x + c) % n

    while g == 1:
        x = y

        for _ in range(r):
            y = brent(c, n, y)
        
        k = 0
        while k < r and g == 1:
            ys = y
            for _ in range(min(m, r-k)):
                y = brent(c, n, y)
                q = (q * abs(x-y)) % n
            
            g  = gcd(q, n)
            k += m

        r *= 2

        attempts += 1
        if max_attempts and attempts >= max_attempts:
            return None

    if g == n:
        while True:
            ys = brent(c, n, ys)
            g  = gcd(abs(x-ys), n)

            if g > 1:
                break
    return g


def ecm(n: int, attempts: int=100) -> int:
    """
    Uses Lenstra's Elliptic Curve Method to probabilistically find a factor of `n`.

    Parameters:
        n        (int): Integer to factor.
        attempts (int): Number of attempts to perform.
    
    Returns:
        int: Factor of `n`.
    
    Examples:
        >>> from samson.math.factorization.general import ecm
        >>> ecm(26515460203326943826)
        2

    """
    from samson.math.algebra.curves.weierstrass_curve import WeierstrassCurve
    Polynomial = poly.Polynomial
    ZZ  = integer_ring.ZZ
    gcd = samson_math.gcd

    # For convenience
    peel_ring = False
    if type(n) is int:
        peel_ring = True
        n = ZZ(n)

    R = n.ring
    ring = R/n
    is_poly = type(n) is Polynomial
    for a in range(attempts):
        while True:
            x = R.random(n)
            y = R.random(n)
            a = R.random(n)
            b = (y**2 - x**3 - (a * x)) % n

            g = gcd(4 * a**3 - 27 * b**2, n)
            if g != n:
                break

        # Free factor!
        if is_poly and g.is_monic() and g > R.one or not is_poly and g > R.one:
            if peel_ring:
                g = g.val
            return g

        curve = WeierstrassCurve(a=a, b=b, ring=ring, base_tuple=(x, y))
        curr  = curve.G
        for fac in range(2, 64):
            try:
                curr *= fac
            except NotInvertibleException as e:
                res = gcd(e.parameters['a'], n)
                if res != R.one and (not is_poly or res.is_monic()):
                    if peel_ring:
                        res = res.val

                    return res

    raise ProbabilisticFailureException("Factor not found")



def is_composite_power(n: int, precision: float=0.6) -> (bool, int, int):
    """
    Determines if `n` is a composite power. If it is, the root and exponent are returned.
    This only works for composite roots. See 'is_perfect_power' for prime roots.

    Parameters:
        n           (int): Possible perfect power.
        precision (float): Required precision of natural comprime bases.
    
    Returns:
        (bool, int, int): Formatted as (is_composite_power, root, exponent).
    
    Examples:
        >>> from samson.math.factorization.general import is_composite_power
        >>> is_composite_power(1806031142**10*2)
        (False, None, 0)

        >>> is_composite_power(325221983058579206406111588123469551600**8)
        (True, 325221983058579206406111588123469551600, 8)

    References:
        "DETECTING PERFECT POWERS BY FACTORING INTO COPRIMES" (http://cr.yp.to/lineartime/powers2-20050509.pdf)
    """
    gcd = samson_math.gcd
    kth_root = samson_math.kth_root

    rs = []
    r  = 2
    while True:
        root = n**(1/r)
        if root < 2:
            break

        if abs(n - root**r) / n < precision:
            rs.append(r)

        r += 1

    bases = {item for sublist in [factor(r).keys() for r in rs] for item in sublist}
    curr = n
    factors = {}
    for base in bases:
        factors[base] = 0
        while not curr % base:
            factors[base] += 1
            curr //= base

    d = 0

    for e in [val for val in factors.values() if val]:
        d = gcd(d, e)

    if d < 2:
        return False, None, 0

    root = kth_root(n, d)
    return root**d == n, root, d



POLLARD_QUICK_ITERATIONS = 25

def factor(n: int, use_trial: bool=True, limit: int=1000, use_rho: bool=True, rho_max_bits: int=90, use_siqs: bool=True, use_pollards_p_1: bool=True, use_ecm: bool=False, ecm_attempts: int=100000, perfect_power_checks: bool=True, mersenne_check: bool=True, visual: bool=False, reraise_interrupt: bool=False, user_stop_func: FunctionType=None) -> list:
    """
    Factors an integer `n` into its prime factors.

    Parameters:
        n                     (int): Integer to factor.
        use_trial            (bool): Whether or not to use trial division.
        limit                 (int): Upper limit of factors tried in trial division.
        use_rho              (bool): Whether or not to use Pollard's rho factorization.
        rho_max_bits          (int): Threshold in which Pollard's rho is considered ineffective.
        use_siqs             (bool): Whether or not to use the Self-Initializing Quadratic Sieve.
        use_pollards_p_1     (bool): Whether or not to use Pollard's P-1.
        use_ecm              (bool): Whether or not to use ECM factorization.
        ecm_attempts          (int): Maximum number of ECM attempts before giving up.
        perfect_power_checks (bool): Whether or not to check for perfect powers.
        mersenne_check       (bool): Whether or not to check if `n` is a Mersenne number and factor accordingly (see `_mersenne_factor`).
        visual               (bool): Whether or not to display progress bar.
        reraise_interrupt    (bool): Whether or not to reraise a KeyboardInterrupt.
        user_stop_func       (func): A function that takes in (n, facs) and returns True if the user wants to stop factoring.

    Returns:
        list: List of factors.
    
    Examples:
        >>> from samson.math.factorization.general import factor
        >>> dict(factor(26515460203326943826)) == {2: 1, 3262271209: 1, 4063957057: 1} # equality because pytest sorts dicts weird
        True

    """
    is_prime = samson_math.is_prime
    is_power_of_two = samson_math.is_power_of_two

    original = n

    if not user_stop_func:
        user_stop_func = lambda n, facs: False

    factors = Factors()

    # Handle negatives
    if n < 0:
        factors[-1] = 1
        n //= -1

    # Handle [0, 1] or prime
    if n < 2 or is_prime(n):
        factors[n] = 1
        return Factors(factors)


    def calc_prog(x):
        return round(math.log(x, 2), 2)

    def is_factored(n):
        return n == 1 or is_prime(n) or user_stop_func(n, factors)


    # Set up visual updates
    if visual:
        progress = tqdm(None, total=calc_prog(n), unit='bit', desc="factor: Bits factored")
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


    # We want to check for perfect powers after every found factor
    # It's relatively cheap and can instantly factor the rest
    def check_perfect_powers(n):
        if perfect_power_checks and not is_factored(n):
            ipp, root, k = is_perfect_power(n)
            if ipp:
                for fac, exponent in factor(root).items():
                    e_k = exponent*k
                    factors.add(fac, e_k)

                    rek = fac**e_k
                    progress_update(rek)
                    n //= rek

        return n
    

    def process_possible_composite(n, f):
        for fac, exponent in factor(f).items():
            factors.add(fac, exponent)
            progress_update(fac**exponent)
            n //= fac**exponent

        return n


    def quick_factor(factor_func, n):
        while not is_factored(n):
            n_fac = factor_func(n)

            if n_fac:
                n = process_possible_composite(n, n_fac)
                n = check_perfect_powers(n)
            else:
                break
        
        return n


    # Actual factorization
    try:
        if mersenne_check and is_power_of_two(original+1):
            k = int(math.log(original+1, 2))
            facs, _ = _mersenne_factor(factor(k), progress_update)
            progress_finish()
            return facs


        if use_trial:
            # Trial division
            trial_facs = trial_division(n, limit=limit, progress_update=progress_update)
            factors += trial_facs
            n //= trial_facs.recombine()
            n = check_perfect_powers(n)


        n_bits = n.bit_length()

        if use_rho:
            # Pollard's rho
            # If `n` is too big, attempt to remove small factors
            if n_bits > rho_max_bits:
                n = quick_factor(lambda n: pollards_rho(n, POLLARD_QUICK_ITERATIONS), n)
                # while not is_factored(n):
                #     n_fac = pollards_rho(n, POLLARD_QUICK_ITERATIONS)

                #     if n_fac:
                #         n = process_possible_composite(n, n_fac)
                #         n = check_perfect_powers(n)
                #     else:
                #         break

            else:
                # Full factorization with 'pollards_rho'
                while not is_factored(n):
                    n_fac = pollards_rho(n)

                    # Rho will give a factor, but not necessarily a prime
                    n = process_possible_composite(n, n_fac)
                    n = check_perfect_powers(n)

        if use_pollards_p_1:
            n = quick_factor(lambda n: pollards_p_1(n, B2=100000), n)
            # while not is_factored(n):
            #     n_fac = pollards_p_1(n, B2=100000)

            #     if n_fac:
            #         n = process_possible_composite(n, n_fac)
            #         n = check_perfect_powers(n)
            #     else:
            #         break

        if use_ecm:
            # Lenstra's ECM
            while not is_factored(n):
                try:
                    n_fac = ecm(n, attempts=ecm_attempts)

                    # ECM will give a factor, but not necessarily a prime
                    n = process_possible_composite(n, n_fac)
                    n = check_perfect_powers(n)

                except ProbabilisticFailureException:
                    break


        if use_siqs:
            while not is_factored(n):
                primes, composites = siqs.siqs(n, visual=visual)
                factors += primes

                n //= primes.recombine()

                for com in composites:
                    n = process_possible_composite(n, com)

                n = check_perfect_powers(n)


    except KeyboardInterrupt:
        if reraise_interrupt:
            raise KeyboardInterrupt()

    progress_finish()
    if n != 1:
        factors.add(n)

    return factors
