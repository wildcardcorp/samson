from samson.utilities.bytes import Bytes
from samson.block_ciphers.modes.ctr import CTR
from samson.macs.cmac import CMAC


class EAX(object):
    """
    EAX block cipher mode
    http://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf
    """

    def __init__(self, cipher_obj: object, nonce: bytes):
        """
        Parameters:
            cipher_obj (object): Instantiated cipher object.
            nonce       (bytes): Bytes-like nonce.
        """
        self.cipher_obj = cipher_obj
        self.nonce = nonce
        self.ctr = CTR(self.cipher_obj.encrypt, b'', self.cipher_obj.block_size)

        self.cmac = CMAC(self.cipher_obj.key, self.cipher_obj.__class__)


    def __repr__(self):
        return f"<EAX: cipher_obj={self.cipher_obj}, nonce={self.nonce}>"

    def __str__(self):
        return self.__repr__()



    def generate_tag(self, ciphertext: bytes, auth_data: bytes) -> Bytes:
        """
        Internal function. Generates a valid tag for the `ciphertext` and `auth_data`.
        """
        cipher_mac = self.cmac.generate(Bytes(2).zfill(self.cipher_obj.block_size) + ciphertext)
        tag = cipher_mac ^ self.cmac.generate(Bytes(0).zfill(self.cipher_obj.block_size) + self.nonce) ^ self.cmac.generate(Bytes(1).zfill(self.cipher_obj.block_size) + Bytes.wrap(auth_data))

        return tag


    def encrypt(self, plaintext: bytes, auth_data: bytes) -> Bytes:
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext (bytes): Bytes-like object to be encrypted.
            auth_data (bytes): Bytes-like additional data to be authenticated but not encrypted.
        
        Returns:
            Bytes: Resulting ciphertext.
        """
        self.ctr.counter = self.cmac.generate(Bytes(0).zfill(self.cipher_obj.block_size) + self.nonce).int()

        ciphertext = self.ctr.encrypt(plaintext)
        tag = self.generate_tag(ciphertext, auth_data)

        return ciphertext + tag[:self.cipher_obj.block_size]



    def decrypt(self, ciphertext: bytes, auth_data: bytes, verify: bool=True) -> Bytes:
        """
        Decrypts `ciphertext`.

        Parameters:
            ciphertext (bytes): Bytes-like object to be decrypted.
            auth_data  (bytes): Bytes-like additional data to be authenticated but not encrypted.
            verify      (bool): Whether or not to verify the authentication tag.
        
        Returns:
            Bytes: Resulting plaintext.
        """
        ciphertext, given_tag = ciphertext[:-16], ciphertext[-16:]
        tag = self.generate_tag(ciphertext, auth_data)

        if verify:
            assert tag == given_tag


        self.ctr.counter = self.cmac.generate(Bytes(0).zfill(self.cipher_obj.block_size) + self.nonce).int()
        plaintext = self.ctr.decrypt(ciphertext)


        return plaintext
