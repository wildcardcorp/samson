
def gcd(a, b):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)



def lcm(a, b):
    return a // gcd(a, b) * b


def mod_inv(a, n):
    """
    Calculates the modular inverse according to
    https://en.wikipedia.org/wiki/Euclidean_algorithm#Linear_Diophantine_equations
    and https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
    """

    t = 0
    r = n

    new_t = 1
    new_r = a

    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r
    
    if r > 1:
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
