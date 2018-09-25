
def gcd(a, b):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)


# https://anh.cs.luc.edu/331/notes/xgcd.pdf
def xgcd(a,b):
    prevx, x = 1, 0; prevy, y = 0, 1
    while b:
        q = a//b
        x, prevx = prevx - q*x, x
        y, prevy = prevy - q*y, y
        a, b = b, a % b
    return a, b, prevx, prevy


def lcm(a, b):
    return a // gcd(a, b) * b



def mod_inv(a, n):
    """
    Calculates the modular inverse according to
    https://en.wikipedia.org/wiki/Euclidean_algorithm#Linear_Diophantine_equations
    and https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
    """

    _, b, t, _ = xgcd(a, n)

    if b > 1:
        raise Exception("'a' is not invertible")
    
    if t < 0:
        t = t + n

    return t
    

def modexp (g, u, p):
   """computes s = (g ^ u) mod p
      args are base, exponent, modulus
      (see Bruce Schneier's book, _Applied Cryptography_ p. 244)"""
   s = 1
   while u != 0:
      if u & 1:
         s = (s * g)%p
      u >>= 1
      g = (g * g)%p
   return s


# https://stackoverflow.com/questions/23621833/is-cube-root-integer
def kth_root(n,k):
    lb,ub = 0,n #lower bound, upper bound
    while lb < ub:
        guess = (lb+ub)//2
        if pow(guess,k) < n: lb = guess+1
        else: ub = guess
    return lb


def crt(residues, moduli):
    assert len(residues) == len(moduli)
    x = residues[0]
    Nx = moduli[0]

    for i in range(1, len(residues)):
        x = (mod_inv(Nx, moduli[i]) * (residues[i] - x)) * Nx + x
        Nx = Nx * moduli[i]

    return x % Nx, Nx