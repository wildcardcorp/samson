from samson.utilities.bytes import Bytes
from samson.block_ciphers.modes.ctr import CTR
from samson.macs.cmac import CMAC
from samson.core.primitives import EncryptionAlg, StreamingBlockCipherMode, Primitive, AuthenticatedCipher
from samson.core.metadata import EphemeralType, EphemeralSpec, SizeType, SizeSpec
from samson.ace.decorators import register_primitive

@register_primitive()
class EAX(StreamingBlockCipherMode, AuthenticatedCipher):
    """
    EAX block cipher mode
    http://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf
    """

    EPHEMERAL     = EphemeralSpec(ephemeral_type=EphemeralType.NONCE, size=SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda block_mode: block_mode.cipher.BLOCK_SIZE))
    AUTH_TAG_SIZE = SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda block_mode: block_mode.cipher.BLOCK_SIZE)

    def __init__(self, cipher: EncryptionAlg, nonce: bytes):
        """
        Parameters:
            cipher (EncryptionAlg): Instantiated encryption algorithm.
            nonce          (bytes): Bytes-like nonce.
        """
        Primitive.__init__(self)
        self.cipher = cipher
        self.nonce  = nonce
        self.ctr    = CTR(self.cipher, b'')
        self.cmac   = CMAC(self.cipher)


    def generate_tag(self, ciphertext: bytes, auth_data: bytes) -> Bytes:
        """
        Internal function. Generates a valid tag for the `ciphertext` and `auth_data`.
        """
        cipher_mac = self.cmac.generate(Bytes(2).zfill(self.cipher.block_size) + ciphertext)
        tag = cipher_mac ^ self.cmac.generate(Bytes(0).zfill(self.cipher.block_size) + self.nonce) ^ self.cmac.generate(Bytes(1).zfill(self.cipher.block_size) + Bytes.wrap(auth_data))

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
        self.ctr.counter = self.cmac.generate(Bytes(0).zfill(self.cipher.block_size) + self.nonce).int()

        ciphertext = self.ctr.encrypt(plaintext)
        tag = self.generate_tag(ciphertext, auth_data)

        return ciphertext + tag[:self.cipher.block_size]



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
            self.verify_tag(tag, given_tag)


        self.ctr.counter = self.cmac.generate(Bytes(0).zfill(self.cipher.block_size) + self.nonce).int()
        plaintext = self.ctr.decrypt(ciphertext)


        return plaintext
