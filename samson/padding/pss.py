from samson.utilities.bytes import Bytes
from samson.hashes.sha1 import SHA1
from samson.padding.oaep import MGF1
from types import FunctionType


class PSS(object):
    """
    Probabilistic Signature Scheme used for RSA signatures

    RFC8017 (https://tools.ietf.org/html/rfc8017)
    """

    def __init__(self, modulus_len: int, mgf: FunctionType=MGF1, hash_obj: object=SHA1(), salt_len: int=8):
        """
        Parameters:
            modulus_len (int): Length of the RSA modulus, i.e. RSA bit strength.
            mgf        (func): Mask generation function. Takes in `seed` and `length` and returns bytes.
            hash_obj (object): Instantiated object with compatible hash interface.
            salt_len    (int): Length of salt to generate if salt is not explicitly provided.
        """
        self.modulus_len = modulus_len
        self.mgf = mgf
        self.hash_obj = hash_obj
        self.salt_len = salt_len


    def __repr__(self):
        return f"<PSS: modulus_len={self.modulus_len}, mgf={self.mgf}, hash_obj={self.hash_obj}, salt_len={self.salt_len}>"

    def __str__(self):
        return self.__repr__()


    # https://tools.ietf.org/html/rfc8017#section-9.1.1
    def sign(self, plaintext: bytes, salt: bytes=None) -> Bytes:
        """
        Pads and hashes the `plaintext`.

        Parameters:
            plaintext (bytes): Plaintext to sign.
            salt      (bytes): (Optional) Random salt.
        
        Returns:
            Bytes: Probabilistic signature.
        """
        plaintext = Bytes.wrap(plaintext)
        mHash     = self.hash_obj.hash(plaintext)

        salt    = salt or Bytes.random(self.salt_len)
        m_prime = b'\x00' * 8 + mHash + salt

        H = self.hash_obj.hash(m_prime)

        em_bits = self.modulus_len - 1
        em_len  = (em_bits + 7) // 8
        ps_len = em_len - self.hash_obj.digest_size - self.salt_len - 2

        if ps_len < 0:
            raise ValueError("Plaintext is too long")

        PS = Bytes(b'').zfill(ps_len)

        DB        = PS + b'\x01' + salt
        db_mask   = self.mgf(H, em_len - self.hash_obj.digest_size - 1)
        masked_db = DB ^ db_mask

        # Set the leftmost 8emLen - emBits bits of the leftmost octet in maskedDB to zero.
        masked_db &= (2**(len(masked_db) * 8) - 1) >> ((8 * em_len) - em_bits)

        return masked_db + H + b'\xbc'


    # https://tools.ietf.org/html/rfc8017#section-9.1.2
    def verify(self, plaintext: bytes, signature: bytes) -> bool:
        """
        Verifies the `plaintext` against the `signature`.

        Parameters:
            plaintext (bytes): Plaintext to verify.
            signature (bytes): Signature to verify against plaintext.
        
        Returns:
            bool: Whether or not the plaintext is verified.
        """
        from samson.utilities.runtime import RUNTIME

        plaintext = Bytes.wrap(plaintext)
        signature = Bytes.wrap(signature).zfill((self.modulus_len + 7) // 8)
        mHash     = self.hash_obj.hash(plaintext)

        em_bits = self.modulus_len - 1
        em_len  = (em_bits + 7) // 8

        if em_len < (self.hash_obj.digest_size + self.salt_len + 2):
            return False

        if bytes([signature[-1]]) != b'\xbc':
            return False


        # Let maskedDB be the leftmost emLen - hLen - 1 octets of EM,
        #    and let H be the next hLen octets.
        mask_len  = em_len - self.hash_obj.digest_size - 1
        masked_db = signature[:mask_len]
        H         = signature[mask_len:mask_len + self.hash_obj.digest_size]

        # If the leftmost 8emLen - emBits bits of the leftmost octet in
        #    maskedDB are not all equal to zero, output "inconsistent" and
        #    stop.
        left_mask = (2**(len(masked_db) * 8) - 1) >> ((8 * em_len) - em_bits)
        if masked_db & left_mask != masked_db:
            return False

        db_mask = self.mgf(H, mask_len)
        DB      = masked_db ^ db_mask
        DB     &= left_mask

        # If the emLen - hLen - sLen - 2 leftmost octets of DB are not
        #    zero or if the octet at position emLen - hLen - sLen - 1 (the
        #    leftmost position is "position 1") does not have hexadecimal
        #    value 0x01, output "inconsistent" and stop.
        if DB[:em_len - self.hash_obj.digest_size - self.salt_len - 1].int() != 1:
            return False

        salt    = DB[-self.salt_len:] if self.salt_len else b''
        m_prime = b'\x00' * 8 + mHash + salt
        h_prime = self.hash_obj.hash(m_prime)

        return RUNTIME.compare_bytes(h_prime, H)
