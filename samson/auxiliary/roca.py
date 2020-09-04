from samson.math.general import next_prime, pohlig_hellman, is_prime, random_int_between
from samson.math.algebra.rings.integer_ring import ZZ
from samson.utilities.exceptions import SearchspaceExhaustedException


# "Optimization of the ROCA (CVE-2017-15361) Attack"
M_PRIME_TABLE = {
    512:  (0x1b3e6c9433a7735fa5fc479ffe4027e13bea, 5, 6, 0x80000),
    1024: (0x24683144f41188c2b1d6a217f81f12888e4e6513c43f3f60e72af8bd9728807483425d1e, 4, 5, 0x40000000),
    2048: (0x016928dc3e47b44daf289a60e80e1fc6bd7648d7ef60d1890f3e0a9455efe0abdb7a748131413cebd2e36a76a355c1b664be462e115ac330f9c13344f8f3d1034a02c23396e6, 7, 8, 0x400000000)
}

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
        p = next_prime(p+1)
        M *= p

    return M


def get_params(bit_size):
    if bit_size < 992:
        return M_PRIME_TABLE[512]
    elif bit_size < 1984:
        return M_PRIME_TABLE[1024]
    else:
        return M_PRIME_TABLE[2048]



def check_roca(N):
    Mp, _, _, _ = get_params(N.bit_length())
    try:
        Zm = (ZZ/ZZ(Mp)).mul_group()
        g  = Zm(65537)
        _  = pohlig_hellman(g, Zm(N))
        return True
    except SearchspaceExhaustedException:
        return False


# LSB bias
def add_parity_bias(a: int):
    lsb = random_int_between(0, 99) > 89
    if a & 1 == lsb:
        return a
    else:
        return a ^ 1


def gen_roca_prime(bit_size: int):
    M      = gen_M(bit_size*2)
    M_size = M.bit_length()
    p      = 4
    k_size = bit_size-M_size-1

    # Here we're manually adding the MSB bias
    Mp, _, _, c_a = get_params(bit_size*2)
    Zm     = (ZZ/ZZ(Mp)).mul_group()
    max_a  = Zm(65537).order

    while not is_prime(p):
        k = random_int_between(2**k_size+1 , 2**(k_size+1))
        a = random_int_between(c_a, max_a)
        a = add_parity_bias(a)
        p = k*M + pow(65537, a, M)

    return p, k, a, M
