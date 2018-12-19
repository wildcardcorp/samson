from samson.hashes.sha2 import SHA512
from samson.kdfs.bcrypt import Bcrypt
from samson.utilities.bytes import Bytes

# OpenSSH's custom PBKDF2
# https://github.com/openssh/openssh-portable/blob/90e51d672711c19a36573be1785caf35019ae7a8/openbsd-compat/bcrypt_pbkdf.c
class BcryptPBKDF(object):
    """
    The 'bcrypt_pbkdf' function in OpenSSH.
    """

    def __init__(self, rounds: int=16, hash_obj: object=SHA512()):
        """
        Parameters:
            rounds      (int): Number of rounds to perform.
            hash_obj (object): Instantiated object with compatible hash interface. Normally SHA512.
        """
        self.rounds = rounds
        self.hash_obj = hash_obj


    def derive(self, password: bytes, salt: bytes, key_len: int=48) -> Bytes:
        """
        Derives the key.

        Parameters:
            password (bytes): Password.
            salt     (bytes): Salt.
            key_len    (int): Length of key to generate.
        
        Returns:
            Bytes: Derived key.
        """
        orig_key_len = key_len
        salt_len = len(salt)

        salt = Bytes.wrap(salt)

        sha_pass = self.hash_obj.hash(password)

        stride = (key_len + 32 - 1) // 32
        amt = (key_len + stride - 1) // stride
        count_salt = salt + b'\x00' * 4

        key = Bytes(b'').zfill(key_len)
        bcrypt = Bcrypt(cost=6, constant=b'OxychromaticBlowfishSwatDynamite', output_size=32, version=None, use_specs_eks=True)

        count = 1
        while key_len > 1:
            count_salt[salt_len + 0] = (count >> 24) & 0xFF
            count_salt[salt_len + 1] = (count >> 16) & 0xFF
            count_salt[salt_len + 2] = (count >>  8) & 0xFF
            count_salt[salt_len + 3] = (count >>  0) & 0xFF

            sha_salt = self.hash_obj.hash(count_salt)

            out = bcrypt.derive(sha_pass, sha_salt, format_output=False)
            out = sum([chunk[::-1] for chunk in out.chunk(4)])
            tmp_out = out


            for _ in range(1, self.rounds):
                sha_salt = self.hash_obj.hash(tmp_out)
                tmp_out = bcrypt.derive(sha_pass, sha_salt, format_output=False)
                tmp_out = sum([chunk[::-1] for chunk in tmp_out.chunk(4)])
                out ^= tmp_out

            amt = min(amt, key_len)
            for i in range(amt):
                dest = i * stride + (count - 1)
                if dest >= orig_key_len:
                    break

                key[dest] = out[i]

            key_len -= (i + 1)
            count += 1

        return key
