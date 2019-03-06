from samson.utilities.bytes import Bytes
from types import FunctionType
from samson.kdfs.pbkdf2 import PBKDF2
from samson.macs.hmac import HMAC
from samson.hashes.sha2 import SHA256
from samson.stream_ciphers.salsa import Salsa

NULL_SALSA = Salsa(key=Bytes(b'').zfill(8), nonce=Bytes(b'').zfill(8), rounds=8)

def BlockMix(B):
    r = len(B) // 128
    B_arr = B.chunk(64)

    X = B_arr[-1]
    Y = []
    for i in range(2*r):
        T = X ^ B_arr[i]
        T.byteorder = 'little'

        X = NULL_SALSA.full_round(0, state=[x.int() for x in T.chunk(4)])
        Y.append(X)


    Y_ret = b''.join([_ for _ in Y[::2]]) + b''.join([_ for _ in Y[1::2]])
    return Bytes(Y_ret)



def ROMix(block, iterations):
    X = block
    V = []
    for _ in range(iterations):
        X.byteorder = 'little'
        V.append(X)
        X = BlockMix(X)


    for _ in range(iterations):
        X.byteorder = 'little'
        j = X[-64:].int() % iterations
        X = BlockMix(X ^ V[j])

    return X


class Scrypt(object):
    """
    scrypt KDF described in RFC7914
    https://en.wikipedia.org/wiki/Scrypt
    https://tools.ietf.org/html/rfc7914
    """

    def __init__(self, desired_len: int, cost: int, parallelization_factor: int, block_size_factor: int=8, hash_fn: FunctionType=lambda passwd, msg: HMAC(passwd, SHA256()).generate(msg)):
        """
        Parameters:
            desired_len         (int): Desired output length.
            cost                (int): Cost (usually a power of two).
            block_size_factor   (int): `r` from the RFC.
            hash_fn            (func): Function that takes in bytes and returns them hashed.
        """
        self.block_size = block_size_factor * 128
        self.hash_fn = hash_fn
        self.pbkdf2 = PBKDF2(hash_fn,  self.block_size * parallelization_factor, 1)
        self.desired_len = desired_len
        self.cost = cost
        self.block_size_factor = block_size_factor
        self.parallelization_factor = parallelization_factor


    def __repr__(self):
        return f"<Scrypt: pbkdf2={self.pbkdf2}, desired_len={self.desired_len}, cost={self.cost}, block_size={self.block_size}>"

    def __str__(self):
        return self.__repr__()


    def derive(self, password: bytes, salt: bytes) -> Bytes:
        """
        Derives a key.

        Parameters:
            password (bytes): Bytes-like object to key the internal state.
            salt     (bytes): Salt to tweak the output.
        
        Returns:
            Bytes: Derived key.
        """
        B = self.pbkdf2.derive(password, salt).chunk(self.block_size)

        for i in range(self.parallelization_factor):
            B[i] = ROMix(B[i], self.cost)

        expensive_salt = b''.join(B)
        return PBKDF2(self.hash_fn, self.desired_len, 1).derive(password, expensive_salt)
