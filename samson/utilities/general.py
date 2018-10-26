import random

URANDOM = open("/dev/urandom", "rb")


def rand_bytes(size=16):
    return URANDOM.read(size)


def shuffle(in_list):
    random.shuffle(in_list, lambda: int.from_bytes(rand_bytes(32), 'big') / (2 ** 256))


def de_bruijn(k, n):
  """
  de Bruijn sequence for alphabet k
  and subsequences of length n.
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
