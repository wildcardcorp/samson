from samson.utilities.bytes import Bytes
from samson.hashes.md5 import MD5

class RADIUS(object):
    """
    Remote Authentication Dial In User Service (https://tools.ietf.org/html/rfc2865)
    """


    def __init__(self, key: bytes):
        """
        Parameters:
            key (bytes): Encryption key.
        """
        self.key = key


    def __repr__(self):
        return f"<RADIUS: key={self.key}>"

    def __str__(self):
        return self.__repr__()



    def encrypt(self, authenticator: bytes, password: bytes) -> Bytes:
        """
        Encrypts the `password`.

        Parameters:
            authenticator (bytes): Client authenticator.
            password      (bytes): Password.
        
        Returns:
            Bytes: RADIUS-encrypted password.
        """
        if len(password) > 128:
            raise ValueError('Password exceeds maximum of 128 bytes')

        password = Bytes.wrap(password).pad_congruent_right(16)
        md5 = MD5()

        result, last = Bytes(), authenticator
        for chunk in password.chunk(16):
            result += md5.hash(self.key + last) ^ chunk
            last    = result[-16:]

        return result


    def decrypt(self, authenticator: bytes, encrypted_password: bytes) -> Bytes:
        """
        Decrypts the `encrypted_password`.

        Parameters:
            authenticator      (bytes): Client authenticator.
            encrypted_password (bytes): RADIUS-encrypted password.
        
        Returns:
            Bytes: Plaintext password.
        """
        return Bytes(self.encrypt(authenticator, encrypted_password).rstrip(b'\x00'))


    @staticmethod
    def recover_key_hash(encrypted_password: bytes, password: bytes) -> Bytes:
        """
        Performs a known-plaintext attack on RADIUS encryption giving the key hash.

        Parameters:
            encrypted_password (bytes): Password encrypted by RADIUS authentication.
            password           (bytes): Plaintext password.
        
        Returns:
            Bytes: RADIUS key hash as MD5(key + AUTHENTICATOR).

        Examples:
            >>> from samson.protocols.radius import RADIUS
            >>> from samson.utilities.bytes import Bytes
            >>> from samson.hashes.md5 import MD5

            >>> rad     = RADIUS(Bytes.random(32))
            >>> c_salt  = Bytes.random(16)
            >>> my_pass = b'mypass'

            >>> enc_pass = rad.encrypt(c_salt, my_pass)
            >>> RADIUS.recover_key_hash(enc_pass, my_pass) == MD5().hash(rad.key + c_salt)
            True

        """
        return encrypted_password ^ Bytes(password).pad_congruent_right(16)
