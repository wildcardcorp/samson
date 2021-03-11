from samson.math.general import is_prime, totient
from samson.math.algebra.rings.integer_ring import ZZ
from samson.utilities.manipulation import reverse_bits

from samson.auxiliary.lazy_loader import LazyLoader
_dense_vector = LazyLoader('_dense_vector', globals(), 'samson.math.dense_vector')


def find_suitable_prime(X: list, Y: list) -> int:
    n = len(X)
    p = int(max(X + Y)**2*n+1)
    while not is_prime(p):
        p += n

    return p


def find_primitive_root(R: 'Ring', degree: int) -> 'RingElement':
    phi = totient(R.order())
    g   = R.mul_group().find_gen().val
    r   = g**(phi // degree)
    return r


def build_power_table(w, n):
    pow_table = []
    temp      = w.ring.one

    for _ in range(n // 2):
        pow_table.append(temp)
        temp *= w
    
    return pow_table


def find_parameters(X, Y):
    n = len(X)
    p = find_suitable_prime(X, Y)
    R = ZZ/ZZ(p)
    w = find_primitive_root(R, n)

    pow_table = build_power_table(w, n)
    inv_table = build_power_table(~w, n)

    return R, pow_table, inv_table


def linear_convolution(X: list, Y: list) -> 'DenseVector':
    lx = len(X)
    ly = len(Y)
    n  = 2**max(2*lx, 2*ly).bit_length()
    Xn = [0]*(n - lx) + X
    Yn = [0]*(n - ly) + Y
    return circular_convolution(Xn, Yn)[-(lx+ly):]



def circular_convolution(X: list, Y: list) -> 'DenseVector':
    n  = len(X)
    Xn = [0]*(n - len(X)) + X
    Yn = [0]*(n - len(Y)) + Y

    R, pow_table, inv_table = find_parameters(Xn, Yn)

    Xn = _dense_vector.DenseVector(Xn, R)
    Yn = _dense_vector.DenseVector(Yn, R)

    Xf = fft(Xn, pow_table)
    Yf = fft(Yn, pow_table)

    result = fft([a*b for a,b in zip(Xf, Yf)], inv_table)
    n_inv  = ~R(n)
    return [(r*n_inv).val for r in result]




def fft(X: 'DenseVector', pow_table: list) -> 'DenseVector':
    X  = X.copy()
    n  = len(X)
    nb = n.bit_length()-1

    for i in range(n):
        j = reverse_bits(i, nb)
        if j > i:
            X[i], X[j] = X[j], X[i]


    for level in range(1, n.bit_length()):
        size       = 2**level
        half_size  = size // 2
        table_step = n // size

        for i in range(0, n, size):
            k = 0
            for j in range(i, i+half_size):
                l     = j + half_size
                left  = X[j]
                right = X[l] * pow_table[k]

                X[j] = left + right
                X[l] = left - right
                k   += table_step

    return X
