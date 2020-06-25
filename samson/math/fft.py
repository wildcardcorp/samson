from samson.math.sparse_vector import SparseVector
from math import ceil, log


def _split(v, m, k):
    K      = 1<< (k-1)
    zero   = v[0].ring.zero
    zeroes = [zero] * K
    return [v[i:i+K] + zeroes for i in range(0, K << m, K)]


def _combine(L, m, k):
    M = 1 << m
    half_K = 1 << (k-1)
    return SparseVector.wrap(L[0][:half_K] + \
        [L[i+1][j] + L[i][j+half_K] \
            for i in range(M-1) for j in range(half_K)])


def _nega_combine(L, m, k):
    M = 1 << m
    half_K = 1 << (k-1)
    return SparseVector.wrap([L[0][j] - L[M-1][j+half_K] for j in range(half_K)] + \
        [L[i+1][j] + L[i][j+half_K] \
            for i in range(M-1) for j in range(half_K)])



def _forward_butterfly(L1, L2, r):
    assert len(L1) == len(L2)
    assert 0 <= r <= len(L1)

    K = len(L1)
    zero = L1[0].ring.zero
    nL1 = SparseVector([], zero)
    nL2 = SparseVector([], zero)

    indices = set(L1.values.keys()[:] + [(k+r)%K for k in L2.values.keys()])

    for i in indices:
        a = L1[i]
        b = L2[(i-r)%K]

        nL1[i] = a-b
        nL2[i] = a+b


    v1 = nL1[:r] + nL2[r:]
    v2 = nL2[:r] + nL1[r:]

    v1.virtual_len = K
    v2.virtual_len = K

    return v1, v2



def _inverse_butterfly(L1, L2, r):
    assert len(L1) == len(L2)
    assert 0 <= r <= len(L1)

    K = len(L1)
    # print('K', K)
    # print('L1', L1.sparsity)
    # print()

    # zero = L1[0].ring.zero
    # v1 = SparseVector([], zero)
    # v2 = SparseVector([], zero)

    # indices = set(L1.values.keys()[:] + [(r+k)%K for k in L2.values.keys()])

    # for i in indices:
    #     a = L1[i]
    #     b = L2[i]
    #     v1[i] = a + b

    #     if i < r:
    #         c = b - a
    #     else:
    #         c = a - b

    #     v2[(i-r)%K] = c


    # v1.virtual_len = K
    # v2.virtual_len = K

    old_v1 = SparseVector.wrap([L1[i] + L2[i] for i in range(K)])
    old_v2 = SparseVector.wrap([L1[i] - L2[i] for i in range(r, K)] + [L2[i] - L1[i] for i in range(r)])


    # assert v1 == old_v1
    # assert v2 == old_v2

    #return v1, v2
    return old_v1, old_v2



def _fft(L, K, start, depth, root):
    half   = 1 << (depth - 1)
    start2 = start + half

    # reduce mod (x^(D/2) - y^root) and mod (x^(D/2) + y^root)
    for i in range(half):
        if L[start + i].sparsity or L[start2 + i].sparsity:
           L[start + i], L[start2 + i] = \
               _forward_butterfly(L[start + i], L[start2 + i], root)

   # recurse into each half
    if depth >= 2:
        _fft(L, K, start, depth - 1, root >> 1)
        _fft(L, K, start2, depth - 1, (root + K) >> 1)



def _ifft(L, K, start, depth, root):
    half   = 1 << (depth - 1)
    start2 = start + half

    # recurse into each half
    if depth >= 2:
        _ifft(L, K, start, depth - 1, root >> 1)
        _ifft(L, K, start2, depth - 1, (root + K) >> 1)

    # CRT together (x^(D/2) - y^root) and mod (x^(D/2) + y^root)
    for i in range(half):
        if L[start + i].sparsity or L[start2 + i].sparsity:
            L[start + i], L[start2 + i] = \
                _inverse_butterfly(L[start + i], L[start2 + i], root)



def _convolution_naive(L1, L2):
    assert len(L1) and len(L2)

    m1 = len(L1)
    m2 = len(L2)

    zero = L1[0].ring.zero
    new_coeffs = SparseVector([], zero)

    for i, coeff_h in L1:
        for j, coeff_g in L2:
            new_coeffs[i+j] += coeff_h*coeff_g

    return new_coeffs


def _negaconvolution_naive(L1, L2):
    assert len(L1)
    assert len(L1) == len(L2)

    N = len(L1)
    zero = L1[0].ring.zero
    new_coeffs = SparseVector([], zero)

    # for j in range(N):
    #     total = zero
    #     for i in range(N):
    #         c = L1[i] * L2[(j-i)%N]
    #         if i < (j+1):
    #             total += c
    #         else:
    #             total -=c

    #     new_coeffs[j] = total

    # for i, coeff_h in L1:
    #     for j, coeff_g in L2:
    #         if i < (j+1):
    #             new_coeffs[j] += coeff_h*coeff_g
    #         else:
    #             new_coeffs[j] -= coeff_h*coeff_g

    # vals = L2.map(lambda idx, val: (idx, L1[idx]*val))
    # pos_acc = zero
    # neg_acc = sum(vals.list(), zero)

    # for i, coeff in vals:
    #     pos_acc += coeff
    #     neg_acc -= coeff

    #     new_coeffs[i] = pos_acc - neg_acc


    # for i, coeff_h in L1:
    #     for j, coeff_g in L2:
    #         new_coeffs[i+j] += coeff_h*coeff_g

    old_v = SparseVector([sum([L1[i] * L2[j-i] for i in range(j+1)]) - \
    sum([L1[i] * L2[N+j-i] for i in range(j+1, N)]) for j in range(N)], zero=zero)

    # print('L1', L1)
    # print('L2', L2)
    # #print('vals', vals)
    # print('new_coeffs', new_coeffs)
    # print('old_v', old_v)
    # print()

    #assert new_coeffs == old_v

    return old_v
    #return new_coeffs


def _negaconvolution(L1, L2, n):
    if n <= 3: # arbitrary cutoff
        return _negaconvolution_naive(L1, L2)
    else:
        return _negaconvolution_fft(L1, L2, n)


def _negaconvolution_fft(L1, L2, n):
    R = L1[0].ring

    # split into 2^m pieces of 2^(k-1) coefficients each, with k as small
    # as possible, subject to m <= k (so that the ring of Fourier coefficients
    # has enough roots of unity)
    m = (n + 1) >> 1
    k = n + 1 - m

    M = 1 << m
    K = 1 << k

    # split inputs into polynomials
    L1 = _split(L1, m, k)
    L2 = _split(L2, m, k)

    # fft each input
    _fft(L1, K, 0, m, K >> 1)
    _fft(L2, K, 0, m, K >> 1)

    # pointwise multiply
    L3 = [_negaconvolution(L1[i], L2[i], k) for i in range(M)]

    # inverse fft
    _ifft(L3, K, 0, m, K >> 1)

    # combine back into a single list
    L3 = _nega_combine(L3, m, k)

    # normalise
    return L3.map(lambda idx, val: (idx, R(val / M)))



# TODO: Currently, this is all heavily ripped out of Sage. Will require a complete rework.
def _convolution(L1, L2):
    """
    Generalized Schonhage-Strassen polynomial multiplication for arbitrary rings. Very much pulled from Sage.

    References:
        "Fast Multiplication of Polynomials over Arbitrary Rings" (http://kaltofen.math.ncsu.edu/bibliography/87/CaKa87_techrep.pdf)
        https://github.com/sagemath/sage/blob/860e4dc9881966a36ef8808a0d1fae0c6b54f741/src/sage/rings/polynomial/convolution.py#L368
    """
    R = L1[0].ring

    # choose n so that output convolution length is 2^n
    len1 = len(L1)
    len2 = len(L2)
    outlen = len1 + len2 - 1
    n = int(ceil(log(outlen, 2)))

    # split into 2^m pieces of 2^(k-1) coefficients each, with k as small
    # as possible, subject to m <= k + 1 (so that the ring of Fourier
    # coefficients has enough roots of unity)
    m = (n >> 1) + 1
    k = n + 1 - m

    N = 1 << n
    M = 1 << m
    K = 1 << k

    # zero pad inputs up to length N
    zero = R.zero
    L1 += [zero] * (N - len1)
    L2 += [zero] * (N - len2)

    # split inputs into polynomials
    L1 = _split(L1, m, k)
    L2 = _split(L2, m, k)

    # fft each input
    _fft(L1, K, 0, m, K)
    _fft(L2, K, 0, m, K)

    # pointwise multiply
    L3 = [_negaconvolution(L1[i], L2[i], k) for i in range(M)]

    # inverse fft
    _ifft(L3, K, 0, m, K)

    # combine back into a single list
    L3 = _combine(L3, m, k)

    # normalise, and truncate to correct length
    return L3.map(lambda idx, val: (idx, R(val / M)))
