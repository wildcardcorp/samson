from samson.block_ciphers.blowfish import Blowfish
from samson.block_ciphers.modes.ecb import ECB
from samson.utilities.encoding import bcrypt_b64_encode
from samson.utilities.bytes import Bytes

CONSTANT = b"OrpheanBeholderScryDoubt"

# https://en.wikipedia.org/wiki/Bcrypt
# Tested against https://github.com/fwenzel/python-bcrypt
class Bcrypt(object):
    """
    Blowfish based password-hashing algorithm
    """

    def __init__(self, cost: int, constant: bytes=CONSTANT, output_size: int=23):
        """
        Parameters:
            cost        (int): Cost factor.
            constant  (bytes): (Optional) The constant or magic to use for bcrypt.
            output_size (int): (Optional) Size to limit output to.
        """
        self.cost = cost
        self.constant = Bytes.wrap(constant)
        self.output_size = output_size


    def __repr__(self):
        return f"<Bcrypt: cost={self.cost}, constant={self.constant}, output_size={self.output_size}>"

    def __str__(self):
        return self.__repr__()


    def eks_blowfish_setup(self, salt: bytes, password: bytes) -> Blowfish:
        """
        Internal function. Creates a Blowfish instance using the expensive key schedule.

        Parameters:
            salt     (bytes): Salt.
            password (bytes): Password.
        
        Returns:
            Blowfish: Blowfish instance set-up using the expensive key schedule
        """
        bf = Blowfish(b'', run_key_schedule=False)
        key_len = len(password) + 1
        self.expand_key(bf, salt, password, key_len=key_len)

        for _ in range(2**self.cost):
            self.expand_key(bf, Bytes(b'').zfill(16), password, key_len=key_len)
            self.expand_key(bf, Bytes(b'').zfill(16), salt)

        return bf


    def expand_key(self, bf: Blowfish, salt: bytes, password: bytes, key_len: int=None) -> Blowfish:
        """
        Internal function. Performs a round of key expansion for the expensive key schedule.

        Parameters:
            bf    (Blowfish): Blowfish instance to tweak.
            salt     (bytes): Salt.
            password (bytes): Password.
            key_len    (int): Desired length of key. Will zero pad right.
        
        Returns:
            Blowfish: Blowfish instance undergone a round of key expansion.
        """
        if not key_len:
            key_len = len(password)

        stretched = (password + b'\x00' * (key_len - len(password))).stretch(key_len*4)
        password_chunks = stretched.chunk(4)
        for n in range(18):
            bf.P[n] ^= password_chunks[n % len(password_chunks)].int()

        salt_chunks = salt.chunk(4)
        salt_idx = 0
        L = R = 0
        for box in [bf.P] + bf.S:
            for i in range(0, len(box), 2):
                L ^= salt_chunks[salt_idx  ].int()
                R ^= salt_chunks[salt_idx+1].int()

                salt_idx = (salt_idx + 2) % 4

                R, L = bf.enc_L_R(L, R)
                box[i], box[i + 1] = L, R

        return bf



    def derive(self, password: bytes, salt: bytes=None) -> Bytes:
        """
        Derives the bcrypt hash.

        Parameters:
            password (bytes): Password.
            salt     (bytes): Salt.
        
        Returns:
            Bytes: Derived key/hash.
        """
        if not salt:
            salt = Bytes.random(16)

        salt = Bytes.wrap(salt)
        password = Bytes.wrap(password)
        bf = self.eks_blowfish_setup(salt, password)

        ciphertext = self.constant
        ecb = ECB(bf.encrypt, bf.decrypt, bf.block_size)

        for _ in range(64):
            ciphertext = ecb.encrypt(ciphertext)

        return Bytes(b'$2a$' + str(self.cost).zfill(2).encode('utf-8') + b'$' + bcrypt_b64_encode(salt) + bcrypt_b64_encode(ciphertext[:self.output_size]))
