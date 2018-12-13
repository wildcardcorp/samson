from samson.constructions.merkle_damgard_construction import MerkleDamgardConstruction
from samson.utilities.bytes import Bytes
from samson.utilities.manipulation import right_rotate, get_blocks

# https://en.wikipedia.org/wiki/SHA-2
H_256 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
H_224 = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4]
H_512 = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]
H_384 = [0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4]

ROT_256 = [7, 18, 3, 17, 19, 10, 6, 11, 25, 2, 13, 22]
ROT_512 = [1, 8, 7, 19, 61, 6, 14, 18, 41, 28, 34, 39]

K_256 = [
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

K_512 = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
]


class SHA2(MerkleDamgardConstruction):
    """
    SHA2 hash function base class.
    """

    def __init__(self, initial_state: list, digest_size: int, state_size: int, block_size: int, rounds: int, rot: list, k: list):
        """
        Parameters:
            initial_state (list): Initial state as list of integers.
            digest_size    (int): Output size in bytes.
            state_size     (int): Number of elements in state.
            block_size     (int): Amount of message to digest at a time.
            rounds         (int): Number of compression rounds to perform.
            rot           (list): Rotation constants.
            k             (list): `k` constants.
        """
        super().__init__(
            initial_state=Bytes(b''.join([int.to_bytes(h_i, state_size, 'big') for h_i in initial_state])),
            compression_func=None,
            digest_size=digest_size,
            block_size=block_size
        )

        self.state_size = state_size
        self.rounds = rounds
        self.rot = rot
        self.k = k



    def yield_state(self, message: bytes):
        """
        Yields successive states while processing `message`.

        Parameters:
            message (bytes): Message to hash.
        
        Returns:
            generator: Generator yielding states.
        """
        for state in MerkleDamgardConstruction.yield_state(self, message):
            yield state[:self.digest_size]



    def __repr__(self):
        return "<SHA2: initial_state={}, block_size={}, digest_size={}>".format(self.initial_state, self.block_size, self.digest_size)

    def __str__(self):
        return self.__repr__()


    def compression_func(self, block: bytes, state: bytes) -> Bytes:
        """
        SHA-2 compression function.

        Parameters:
            block (bytes): Block being digested.
            state (bytes): Current digest state.
        
        Returns:
            Bytes: Hash output.
        """
        bit_mask = 0xFFFFFFFF if self.state_size == 4 else 0xFFFFFFFFFFFFFFFF
        bit_size = self.state_size * 8

        state = [int.from_bytes(chunk, 'big') for chunk in state.chunk(self.state_size)]
        w = [int.from_bytes(b, 'big') for b in get_blocks(block, self.state_size)] + ([None] * (self.rounds - 16))

        for i in range(16, self.rounds):
            s0 = right_rotate(w[i-15], self.rot[0], bit_size) ^ right_rotate(w[i-15], self.rot[1], bit_size) ^ (w[i-15] >> self.rot[2])
            s1 = right_rotate(w[i-2], self.rot[3], bit_size) ^ right_rotate(w[i-2], self.rot[4], bit_size) ^ (w[i-2] >> self.rot[5])
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & bit_mask


        a = state[0]
        b = state[1]
        c = state[2]
        d = state[3]
        e = state[4]
        f = state[5]
        g = state[6]
        h = state[7]

        for i in range(self.rounds):
            S1 = right_rotate(e,  self.rot[6], bit_size) ^ right_rotate(e, self.rot[7], bit_size) ^ right_rotate(e, self.rot[8], bit_size)
            ch = g ^ (e & (f ^ g))
            temp1 = (h + S1 + ch + self.k[i] + w[i])
            S0 = right_rotate(a, self.rot[9], bit_size) ^ right_rotate(a, self.rot[10], bit_size) ^ right_rotate(a, self.rot[11], bit_size)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj)

            h = g
            g = f
            f = e
            e = (d + temp1) & bit_mask
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & bit_mask


        state[0] += a
        state[1] += b
        state[2] += c
        state[3] += d
        state[4] += e
        state[5] += f
        state[6] += g
        state[7] += h

        return Bytes(b''.join([int.to_bytes(h_i & bit_mask, self.state_size, 'big') for h_i in state]))


class SHA224(SHA2):
    def __init__(self, h: list=None):
        """
        Parameters:
            h (list): Initial state as list of integers.
        """
        super().__init__(
            initial_state=h or H_224,
            digest_size=224 // 8,
            state_size=4,
            block_size=64,
            rounds=64,
            rot=ROT_256,
            k=K_256
        )


class SHA256(SHA2):
    def __init__(self, h: list=None):
        """
        Parameters:
            h (list): Initial state as list of integers.
        """
        super().__init__(
            initial_state=h or H_256,
            digest_size=256 // 8,
            state_size=4,
            block_size=64,
            rounds=64,
            rot=ROT_256,
            k=K_256
        )


class SHA384(SHA2):
    def __init__(self, h: list=None):
        """
        Parameters:
            h (list): Initial state as list of integers.
        """
        super().__init__(
            initial_state=h or H_384,
            digest_size=384 // 8,
            state_size=8,
            block_size=128,
            rounds=80,
            rot=ROT_512,
            k=K_512
        )


class SHA512(SHA2):
    def __init__(self, h: list=None):
        """
        Parameters:
            h (list): Initial state as list of integers.
        """
        super().__init__(
            initial_state=h or H_512,
            digest_size=512 // 8,
            state_size=8,
            block_size=128,
            rounds=80,
            rot=ROT_512,
            k=K_512
        )
