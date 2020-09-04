from samson.math.factorization.siqs import BMatrix, ge_f2_nullspace, solve_row
from samson.utilities.exceptions import NoSolutionException
from samson.math.all import *
import math


def gen_num_field(n, d):
    m = next_prime(max(int(math.pow(n, 1.0/d)), 31))
    f = int_to_poly(n, m)

    while f.degree() > d and not f.is_irreducible():
        m -= 2
        while not is_prime(m):
            m -= 2

        f = int_to_poly(n, m)
        print(f, m)

    return f.peel_coeffs(), m



def alg_base(f, primes):
    A = []
    for p in primes:
        for r in range(p):
            if not f(r) % p:
                A.append((r, p))
    return A



def rat_is_factored(facs, a, b, m):
    return product(facs) == abs(a+b*m)


def alg_is_factored(facs, a, b, f_q, d):
    return product([p for r,p in facs]) == abs((-b)**d*f_q(QQ((-a, b))))



def num_req_primes(n, m, nfs_poly, smooths):
    d = nfs_poly.degree()
    longest = math.ceil(math.log(d, 2) * (d+5) / 2)
    max_u = 0
    for smooth in smooths:
        max_u = max(max_u, *smooth)

    b = 2 * max_u * kth_root(d, 2)*m
    return longest + math.ceil(len(smooths)*math.log(b, 2) / 2)



def gen_primes(primes, f, couv_bound):
    primes_prod = 1

    if primes:
        primes_prod = product(primes)

    sum_bound   = primes_prod.bit_length()

    while sum_bound <= couv_bound:
        p = find_prime(64)
        if p in primes or not f.change_ring(ZZ/ZZ(p)).is_irreducible():
            continue

        primes_prod *= p
        sum_bound    = primes_prod.bit_length()
        primes.append(p)

    return primes, primes_prod


def calc_norm(a, b, f):
    d     = f.degree()
    total = 0
    for i in range(d+1):
        sign   = -1 + 2*(i % 2)
        total += sign * (f.coeffs[d-i]*(a**(d-i))*(b**i))

    return total


def gen_exp_vec(num, base):
    exps = []
    for prime in base:
        total = 0
        while not num % prime:
            total += 1
            num  //= prime

        exps.append(total)

    return exps



def get_alg_prime_exps(smooths, f, base):
    prime_exps = [0]*len(base)

    for smooth in smooths:
        norm       = calc_norm(*smooth, f)
        prime_exps = [a+b for a,b in zip(prime_exps, gen_exp_vec(norm, base))]

    return prime_exps


def sqrt_mod_n(prime_exps, base, n):
    prod = 1
    for p_exp, b in zip(prime_exps, base):
        p_power = pow(b, p_exp // 2, n)
        prod = (prod * p_power) % n

    return prod



def find_non_residue(nfp, p, e):
    non_res = nfp([1, 1])

    while True:
        test = non_res**((p**e-1) // 2)
        if test == nfp([p-1]):
            return non_res

        non_res += nfp.one



def get_s_r(p, e):
    q   = p**e-1
    ctr = 0

    while not q % 2:
        ctr += 1
        q  //= 2

    return q, ctr



def nfp_sqrt(poly, p, d):
    one     = poly.val.coeff_ring.one
    non_res = find_non_residue(poly.ring, p, d)
    s, r    = get_s_r(p, d)

    lamb = poly ** s
    zeta = non_res ** s
    w    = poly ** ((s+1) // 2)

    while lamb.val[0] != one:
        m = 1
        while (lamb ** (2**m)).val[0] != one:
            m += 1

        w    *= zeta**(2**(r-m-1))
        lamb *= zeta**(2**(r-m))

    return w



def poly_norm_p(poly, p, d):
    return (poly ** ((p**d-1) // (p-1))).val[0]


def alg_sqrt(f, n, m, d, smooths, base):
    primes = []
    base                = set([p for _,p in base])
    couv_bound          = num_req_primes(n, m, f, smooths)
    print(couv_bound)
    primes, primes_prod = gen_primes(primes, f, couv_bound)
    prime_exps          = get_alg_prime_exps(smooths, f, base)

    f_prime = f.derivative()
    total   = 0
    print(primes)

    for p in primes:
        norm_p = sqrt_mod_n(prime_exps, base, p)
        R      = ZZ/ZZ(p)
        f_p    = f.change_ring(R)
        nfp    = f_p.ring/f_p
        print(smooths)
        prod   = product([nfp(list(smooth)) for smooth in smooths])

        prod *= f_prime.change_ring(R)**2
        print('#1#')
        sqrt  = nfp_sqrt(prod, p, d)

        print('#2#')
        if poly_norm_p(sqrt, p, d) != norm_p:
            sqrt = -sqrt

        print('#3#')
        q = primes_prod // p
        x = mod_inv(q, p)
        a = int(sqrt.val(m))

        total = (total + a*x*q) % primes_prod

    if math.log(total) > math.log(primes_prod) // 2:
        total = -total % primes_prod

    return total % n



def sieve(m, f_q, num_required, R, A, Q, d):
    N     = m // 2
    pairs = []
    facs  = []
    b     = 0

    last_len = 0

    while len(pairs) < num_required:
        b += 1

        # if last_len == len(pairs):
        #     N *= 2

        last_len = len(pairs)
        print(last_len)

        for a in range(-N, N+1):
            r_facs = []
            c = a+b*m

            if c < 0:
                r_facs.append(-1)
                c //= -1

            for q in R:
                if c == 1:
                    break

                while c and not c % q:
                    c //= q
                    r_facs.append(q)


            a_facs = []
            for (r, p) in A:
                c = a+b*r
                if not c % p:
                    a_facs.append((r, p))


            if rat_is_factored(r_facs, a, b, m) and alg_is_factored(a_facs, a, b, f_q, d):
                q_facs = [int(legendre(a+b*s, q).value != 1) for s,q in Q]
                pairs.append((a, b))
                facs.append((r_facs, a_facs, q_facs))
            else:
                del r_facs
                del a_facs

    return pairs, facs


def build_matrix(facs, R, A, num_cols):
    exp_vecs = []

    for r_facs, a_facs, q_facs in facs:
        exp_vec  = []
        rat_facs = count_items(r_facs)

        # SIGN
        if -1 in rat_facs:
            exp_vec.append(1)
        else:
            exp_vec.append(0)


        # RATIONAL
        for q in R:
            exp_vec.append(0)
            if q in rat_facs:
                exp_vec[-1] = rat_facs[q] % 2


        # ALGEBRAIC
        for (r, p) in A:
            exp_vec.append(int((r,p) in a_facs))


        exp_vec.extend(q_facs)
        exp_vecs.append(exp_vec)


    exp_ints = [int(''.join([str(int(exp_vec[b])) for b in range(len(exp_vec))])[::-1], 2) for exp_vec in exp_vecs]
    return BMatrix(exp_ints, num_cols=num_cols).T



def gnfs(n, d, R_size=30, A_size=90, Q_size=108):
    x = Symbol('x')
    P = ZZ[x]

    # CONFIGURE SIEVE
    f, m = gen_num_field(n, d)
    print(f, m)
    f_q  = f.change_ring(QQ)
    F    = P/f
    assert f(m) % n == 0

    R = list(sieve_of_eratosthenes(R_size))
    A = alg_base(f, sieve_of_eratosthenes(A_size))
    Q = alg_base(f, [p for p in sieve_of_eratosthenes(Q_size) if p > A[-1][1]])

    k = len(R)
    l = len(A)
    u = len(Q)

    num_cols = l+k+u+1

    # PERFORM SIEVE
    pairs, facs = sieve(m, f_q, num_cols+5, R, A, Q, d)
    bexp_mat    = build_matrix(facs, R, A, num_cols)


    # FIND SOLUTIONS
    solutions, marks, M = ge_f2_nullspace(M=bexp_mat, visual=True)

    if not solutions:
        raise NoSolutionException
    print('solutions', solutions)

    found = False
    while not found:
        for solution in solutions:
            sol_vec = solve_row(solution, M, marks)
            rat_sol = 1

            for idx in sol_vec:
                a, b = pairs[idx]
                rat_sol *= a+b*m

            res = alg_sqrt(f, n, m, d, [pairs[idx] for idx in sol_vec], A)

            print('res', res)
            # print(alg_sol2)

            # res = int(alg_sol.val(m))
            print(rat_sol, res)
            print()
            if is_square(rat_sol):
                rat_sol = kth_root(rat_sol, 2)
                res     = kth_root(res, 2)
                for factor in [gcd(n, abs(rat_sol-res)), gcd(n, abs(rat_sol+res))]:
                    print(factor)
                    if factor not in [1, n]:
                        found = True
                        print(f"FOUND: {factor}")
                        break

                if found:
                    break
