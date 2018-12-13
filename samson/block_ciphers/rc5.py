from samson.utilities.bytes import Bytes
from samson.utilities.manipulation import left_rotate, right_rotate
import math

P_w = [0xB7E1, 0xB7E15163, 0xB7E151628AED2A6B]
Q_w = [0x9E37, 0x9E3779B9, 0x9E3779B97F4A7C15]

# https://en.wikipedia.org/wiki/RC5#Algorithm
class RC5(object):
    """
    Structure: Feistel Network
    Key size: 0-2040 bits
    Block size: 32, 64, 128 bits
    """

    def __init__(self, key: bytes, num_rounds: int=12, block_size: int=128):
        """
        Parameters:
            key      (bytes): Bytes-like object to key the cipher.
            num_rounds (int): Number of rounds to perform.
            block_size (int): The desired block size in bits.
        """
        if not block_size in [32, 64, 128]:
            raise Exception("Invalid block size: must be 32, 64, or 128 bits")

        self.key = Bytes.wrap(key)
        self.num_rounds = num_rounds
        self.block_size = block_size // 2
        self.mod = 2 ** self.block_size
        self.S = self._key_expansion()


    def __repr__(self):
        return f"<RC5: key={self.key}, num_rounds={self.num_rounds}, block_size={self.block_size}, S={self.S}>"


    def __str__(self):
        return self.__repr__()



    def _key_expansion(self):
        b = len(self.key)
        u = self.block_size // 8
        t = 2 * (self.num_rounds + 1)

        if b == 0:
            c = 1
        elif b % u:
            self.key = self.key.zfill(u - b % u + b)
            b = len(self.key)
            c = b // u
        else:
            c = b // u

        const_idx = int(math.log(self.block_size, 2) - 4)

        if b == 0:
            L = [0]
        else:
            L = self.key.chunk(b // c)

        for i in range(b - 1, -1, -1):
            L[i // u] = Bytes.wrap(L[i // u] << 8).int() + self.key[i]

        S = [(P_w[const_idx] + (Q_w[const_idx] * i)) % self.mod for i in range(t)]

        i = j = 0
        A = B = 0

        for _ in range(3 * max(t, c)):
            A = S[i] = left_rotate((S[i] + A + B), 3, bits=self.block_size)
            B = L[j] = left_rotate((L[j] + A + B), (A + B) % self.block_size, bits=self.block_size)
            i = (i + 1) % t
            j = (j + 1) % c

        return S



    def encrypt(self, plaintext: bytes) -> Bytes:
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext (bytes): Bytes-like object to be encrypted.
        
        Returns:
            Bytes: Resulting ciphertext.
        """
        plaintext = Bytes.wrap(plaintext)

        A = plaintext[self.block_size // 8:].int()
        B = plaintext[:self.block_size // 8].int()

        A = (A + self.S[0]) % self.mod
        B = (B + self.S[1]) % self.mod

        for i in range(1, self.num_rounds + 1):
            A = (left_rotate(A ^ B, B % self.block_size, bits=self.block_size) + self.S[2*i]) % self.mod
            B = (left_rotate(B ^ A, A % self.block_size, bits=self.block_size) + self.S[2*i + 1]) % self.mod

        return Bytes(A, 'little').zfill(self.block_size // 8) + Bytes(B, 'little').zfill(self.block_size // 8)



    def decrypt(self, ciphertext: bytes) -> Bytes:
        """
        Decrypts `ciphertext`.

        Parameters:
            ciphertext (bytes): Bytes-like object to be decrypted.
        
        Returns:
            Bytes: Resulting plaintext.
        """
        ciphertext = Bytes.wrap(ciphertext)

        A = ciphertext[:self.block_size // 8].int()
        B = ciphertext[self.block_size // 8:].int()

        for i in range(self.num_rounds, 0, -1):
            B = right_rotate((B - self.S[2*i + 1]) % self.mod, A % self.block_size, bits=self.block_size) ^ A
            A = right_rotate((A - self.S[2*i]) % self.mod, B % self.block_size, bits=self.block_size) ^ B

        A = (A - self.S[0]) % self.mod
        B = (B - self.S[1]) % self.mod

        return (Bytes(A, 'little').zfill(self.block_size // 8) + Bytes(B, 'little').zfill(self.block_size // 8))[::-1]
