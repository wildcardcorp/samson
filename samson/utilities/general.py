import random

URANDOM = open("/dev/urandom", "rb")


def rand_bytes(size: int=16) -> bytes:
    """
    Reads bytes from /dev/urandom.

    Parameters:
        size (int): Number of bytes to read.
    
    Returns:
        bytes: Random bytes.
    """
    return URANDOM.read(size)



def shuffle(in_list: list) -> list:
    """
    Shuffles a list in place using random numbers generated from /dev/urandom.

    Parameters:
        in_list (list): List to be shuffled.
    
    Returns:
        list: in_list shuffled in place.
    """
    random.shuffle(in_list, lambda: int.from_bytes(rand_bytes(32), 'big') / (2 ** 256))



def de_bruijn(k: list, n: int) -> str:
    """
    Generates a de Bruijn sequence for alphabet `k` and subsequences of length `n`.

    Parameters:
        k (list): Alphabet.
        n  (int): Subsequence length.
    
    Returns:
        str: de Bruijn sequence.
    """
    try:
        # let's see if k can be cast to an integer;
        # if so, make our alphabet a list
        _ = int(k)
        alphabet = list(map(str, range(k)))

    except (ValueError, TypeError):
        alphabet = k
        k = len(k)

    a = [0] * k * n
    sequence = []

    def db(t, p):
        if t > n:
            if n % p == 0:
                sequence.extend(a[1:p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)
    db(1, 1)
    return "".join(alphabet[i] for i in sequence)
