from samson.math.general import mod_inv
from sympy import factorint, isprime
from itertools import chain, count
from enum import Enum
import math


class FFTOp(Enum):
    CONVOLVE   = lambda a, b, mod: a*b
    DECONVOLVE = lambda a, b, mod: a*mod_inv(b, mod)


def generate_ntt_params(v1, v2):
    vec_len   = len(v1)
    max_value = max(chain(v1, v2))
    min_mod   = max_value**2 * vec_len + 1

    # Find a modulus
    for offset in count(max(1, min_mod + vec_len - 2)):
        modulus = offset * vec_len + 1

        if isprime(modulus):
            break

    totient = modulus - 1

    # Find a generator
    factors = [f for f,_ in factorint(totient).items()]

    for possible_gen in range(1, modulus):
        if pow(possible_gen, totient, modulus) == 1 and all([pow(possible_gen, totient // f, modulus) != 1 for f in factors]):
            gen = possible_gen
            break

    # Find a primitive root
    root = pow(gen, totient // vec_len, modulus)
    return root, modulus



def ntt(vec: list, root: int, modulus: int):
    t = []
    for i in range(len(vec)):
        n_val = 0
        for j, val in enumerate(vec):
            n_val += val * pow(root, i*j, modulus)
            n_val %= modulus
        
        t.append(n_val)
    return t



def ntt_inv(vec_t: list, root: int, modulus: int):
    vec = ntt(vec_t, mod_inv(root, modulus), modulus)
    scaler = mod_inv(len(vec_t), modulus)
    return [val * scaler % modulus for val in vec]



def prepare_fft(v1, v2):
    v1_len = len(v1)
    v2_len = len(v2)

    # Pad vectors for radix-2 FFT
    max_len = max(v1_len, v2_len)
    vec_len = 2**math.ceil(math.log(max_len*2, 2))
    v1 = v1 + [0]*(vec_len - v1_len)
    v2 = v2 + [0]*(vec_len - v2_len)

    # Prepare NTT twiddle factors
    root, modulus    = generate_ntt_params(v1, v2)
    twiddle_factors  = []
    inv_twid_factors = []

    twiddle  = 1
    inv_twid = 1
    inv_root = mod_inv(root, modulus)

    for _ in range(vec_len // 2):
        twiddle_factors.append(twiddle)
        twiddle = (twiddle * root) % modulus

        inv_twid_factors.append(inv_twid)
        inv_twid = (inv_twid * inv_root) % modulus

    return (v1, v2), root, modulus, twiddle_factors, inv_twid_factors



def fft(vec, modulus, twiddle_factors):
    vec_len = len(vec)
    vec_t   = fft_recurse(vec, twiddle_factors, modulus, vec_len, vec_len)
    return vec_t



def fft_recurse(vec, t_factors, mod, n, N):
    if n == 1:
        return vec

    n_2 = n // 2

    X_e = fft_recurse(vec[0::2], t_factors, mod, n_2, N)
    X_o = fft_recurse(vec[1::2], t_factors, mod, n_2, N)

    N_n = N // n
    for k in range(n_2):
        e = X_e[k]
        o = X_o[k] * t_factors[k*N_n]

        X_e[k] = (e + o) % mod
        X_o[k] = (e - o) % mod
    
    return X_e + X_o


def fft_op(v1, v2, operation: FFTOp=FFTOp.CONVOLVE):
    (v1, v2), _root, modulus, twiddle_factors, inv_twid_factors = prepare_fft(v1, v2)
    v1_t = fft(v1, modulus, twiddle_factors)
    v2_t = fft(v2, modulus, twiddle_factors)

    v3_t   = [operation(a, b, modulus) for a,b in zip(v1_t, v2_t)]
    v3     = fft(v3_t, modulus, inv_twid_factors)
    scaler = mod_inv(len(v1), modulus)
    return [val * scaler % modulus for val in v3]
