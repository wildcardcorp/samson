def karat_deg_2(f, g):
    d          = max(f.degree(), g.degree())+1
    d3         = d // 3
    a, b, c    = f[:d3], f[d3:d3*2], f[d3*2:]
    d, e, f    = g[:d3], g[d3:d3*2], g[d3*2:]
    d0, d1, d2 = karatsuba(a, d), karatsuba(b, e), karatsuba(c, f)

    d01 = karatsuba((a+b), (d+e))
    d02 = karatsuba((a+c), (d+f))
    d12 = karatsuba((b+c), (e+f))
    return (d2 << (d3*4)) + ((d12-d1-d2) << (d3*3)) + ((d02-d2-d0+d1) << (d3*2)) + ((d01-d1-d0) << d3) + d0


def karat_deg_1(f, g):
    d      = max(f.degree(), g.degree())+1
    d2     = d // 2
    a, b   = f[:d2], f[d2:]
    c, d   = g[:d2], g[d2:]
    ac, bd = karatsuba(a, c), karatsuba(b, d)
    return (bd << d2*2) + ((karatsuba((a+b),(c+d)) - bd - ac) << d2) + ac


def karatsuba(f, g):
    """
    References:
        https://eprint.iacr.org/2006/224.pdf
    """
    n = f.degree()
    m = g.degree()
    d = max(n, m)+1

    if n == 0 or m == 0:
        return f*g

    elif not d % 3:
        return karat_deg_2(f, g)

    else:
        return karat_deg_1(f, g)
