from samson.math.general import mod_inv
from samson.utilities.manipulation import transpose
from sympy import factorint, isprime
from itertools import chain, count
import math

def generate_ntt_params(v1, v2):
    vec_len = len(v1)
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



def ntt_convolution(v1, v2):
    root, modulus = generate_ntt_params(v1, v2)
    v1_t = ntt(v1, root, modulus)
    v2_t = ntt(v2, root, modulus)

    v3_t = [a*b for a,b in zip(v1_t, v2_t)]
    return ntt_inv(v3_t, root, modulus)



def ntt_deconvolution(v1, v2):
    root, modulus = generate_ntt_params(v1, v2)
    v1_t = ntt(v1, root, modulus)
    v2_t = ntt(v2, root, modulus)

    v3_t = [a * mod_inv(b, modulus) for a,b in zip(v1_t, v2_t)]
    return ntt_inv(v3_t, root, modulus)


def split_vec(vec):
    vec_even = []
    vec_odd  = []
    for idx, val in enumerate(vec):
        if idx % 2:
            vec_odd.append(val)
        else:
            vec_even.append(val)

    return vec_even, vec_odd


# def fft(v1, v2, operation=ntt_convolution):
#     v1_len = len(v1)
#     v2_len = len(v2)

#     max_len = max(v1_len, v2_len)
#     vec_len = math.ceil(math.log(max_len*2, 2))
#     v1 = v1 + [0]*(vec_len - v1_len)
#     v2 = v2 + [0]*(vec_len - v2_len)

#     return fft_recurse(v1, v2, operation)


# def fft_recurse(v1, v2, operation=ntt_convolution):
#     if len(v1) == 1:


#     v1_e, v1_o = split_vec(v1)
#     v2_e, v2_o = split_vec(v2)

#     return transpose(operation(v1_e, v2_e) + operation(v1_o, v2_o), 2)