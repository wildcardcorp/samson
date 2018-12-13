from samson.utilities.bytes import Bytes
from types import FunctionType

class FeistelNetwork(object):
    """
    Construction for building block ciphers. Operates on half of a plaintext or ciphertext at a time and
    interleaves invocations of the Feistel function. If the Feistel function (`round_func`) is a cryptographically
    secure pseudorandom function, then three rounds are sufficient to make the cipher a psuedorandom permutation.
    Four rounds makes it a strong psuedorandom permutation.
    """

    def __init__(self, round_func: FunctionType, key_schedule: FunctionType):
        """
        Parameter:
            round_func   (func): The Feistel function that takes in a state and subkey and returns a new state. Does not need to be invertible.
            key_schedule (func): Function that takes in a key and returns a list or generator of subkeys.
        """
        self.round_func = round_func
        self.key_schedule = key_schedule


    def __repr__(self):
        return f"<FeistelNetwork round_func={self.round_func}, key_schedule={self.key_schedule}>"

    def __str__(self):
        return self.__repr__()



    def yield_encrypt(self, key: bytes, plaintext: bytes):
        """
        Yields the intermediate, encrypted states of the `plaintext`.

        Parameters:
            key       (bytes): Bytes-like object to key the cipher.
            plaintext (bytes): Bytes-like object to be encrypted.
        
        Returns:
            generator: Resulting intermediate ciphertext.
        """
        half = len(plaintext) // 2
        plaintext = Bytes.wrap(plaintext)
        L_i, R_i = plaintext[:half], plaintext[half:]

        round_keys = list(self.key_schedule(key))

        for subkey in round_keys:
            L_i, R_i = R_i, (L_i ^ self.round_func(R_i, subkey))
            yield R_i, L_i



    def yield_decrypt(self, key: bytes, ciphertext: bytes):
        """
        Yields the intermediate, decrypted states of the `ciphertext`.

        Parameters:
            key        (bytes): Bytes-like object to key the cipher.
            ciphertext (bytes): Bytes-like object to be decrypted.
        
        Returns:
            generator: Resulting intermediate plaintext.
        """
        half = len(ciphertext) // 2
        ciphertext = Bytes.wrap(ciphertext)
        R_i, L_i = ciphertext[:half], ciphertext[half:]

        round_keys = list(self.key_schedule(key))[::-1]

        for subkey in round_keys:
            R_i, L_i = L_i, (R_i ^ self.round_func(L_i, subkey))
            yield L_i, R_i



    def encrypt(self, key: bytes, plaintext: bytes) -> Bytes:
        """
        Encrypts `plaintext` by yielding the final state of the Feistel network.

        Parameters:
            key       (bytes): Bytes-like object to key the cipher.
            plaintext (bytes): Bytes-like object to be encrypted.
        
        Returns:
            Bytes: Resulting ciphertext.
        """
        return Bytes(b''.join(list(self.yield_encrypt(key, plaintext))[-1]))



    def decrypt(self, key: bytes, ciphertext: bytes) -> Bytes:
        """
        Decrypts `ciphertext` by yielding the final state of the Feistel network.

        Parameters:
        key       (bytes): Bytes-like object to key the cipher.
            ciphertext (bytes): Bytes-like object to be decrypted.
        
        Returns:
            Bytes: Resulting plaintext.
        """
        return Bytes(b''.join(list(self.yield_decrypt(key, ciphertext))[-1]))
