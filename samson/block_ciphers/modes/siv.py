from samson.block_ciphers.modes.ctr import CTR
from samson.kdfs.s2v import S2V
from samson.utilities.bytes import Bytes

class SIV(object):
    """
    SIV cipher mode, RFC5297 (https://tools.ietf.org/html/rfc5297)
    """

    def __init__(self, s2v_key: bytes, cipher_obj: object):
        """
        Parameters:
            s2v_key     (bytes): Key used for generating/verifying S2V IV (i.e. `k2` in RFC5297).
            cipher_obj (object): Instantiated cipher object.
        """
        self.s2v_key = s2v_key
        self.cipher_obj = cipher_obj


    def __repr__(self):
        return f"<SIV: cipher_obj={self.cipher_obj}>"

    def __str__(self):
        return self.__repr__()


    def encrypt(self, plaintext: bytes, additional_data: list=[]) -> Bytes:
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext      (bytes): Bytes-like object to be encrypted.
            additional_data (list): Additional data to be authenticated (e.g. headers).
        
        Returns:
            Bytes: Resulting IV + ciphertext.
        """
        iv = S2V(self.s2v_key, self.cipher_obj.__class__).derive(*additional_data, plaintext)

        ctr = CTR(self.cipher_obj.encrypt, Bytes(b''), self.cipher_obj.block_size)
        ctr.counter = iv.int() & 340282366920938463454151235392765951999
        return iv + ctr.encrypt(plaintext)


    def decrypt(self, ciphertext: bytes, additional_data: list=[], verify: bool=True) -> Bytes:
        """
        Decrypts `ciphertext`.

        Parameters:
            ciphertext     (bytes): Bytes-like object to be decrypted.
            additional_data (list): Additional data to be authenticated (e.g. headers).
            verify          (bool): Whether or not to verify the authentication tag.
        
        Returns:
            Bytes: Resulting plaintext.
        """
        ciphertext = Bytes.wrap(ciphertext)
        iv, ct = ciphertext[:16], ciphertext[16:]

        ctr = CTR(self.cipher_obj.encrypt, Bytes(b''), self.cipher_obj.block_size)
        ctr.counter = iv.int() & 340282366920938463454151235392765951999

        plaintext = ctr.decrypt(ct)

        if verify:
            tag = S2V(self.s2v_key, self.cipher_obj.__class__).derive(*additional_data, plaintext)
            assert iv == tag

        return plaintext
