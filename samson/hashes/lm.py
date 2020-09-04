from samson.block_ciphers.des import DES
from samson.utilities.bytes import Bytes
from samson.utilities.runtime import RUNTIME
from samson.core.base_object import BaseObject
import itertools
import string

class LM(BaseObject):
    def __init__(self, plaintext: bytes=b'KGS!@#$%'):
        self.plaintext  = plaintext
        self.block_size = 7


    def hash(self, message: bytes) -> Bytes:
        """
        Hash `message` with LM.

        Parameters:
            message (bytes): Message to be hashed.
        
        Returns:
            Bytes: LM hash.
        """
        key  = Bytes.wrap(message.upper())[:14]
        key += b'\x00' * (14 - len(key))

        # Add parity bits
        key_bits = key.bits()
        key      = Bytes(int(''.join([str(chunk) + '0' for chunk in key_bits.chunk(7)]), 2)).zfill(16)

        return DES(key[:8]).encrypt(self.plaintext) + DES(key[8:]).encrypt(self.plaintext)


    def check_halves_null(self, lm_hash: bytes) -> list:
        """
        Checks if either half of the plaintext is null. LM hashes encrypt each half of the plaintext separately so
        attackers can determine if the plaintext is less than eight characters by checking if the second half is 'aad3b435b51404ee'.

        Parameters:
            lm_hash (bytes): LM hash.
        
        Returns:
            list: Whether or not each half of the LM hash is null.
        """
        return [half == DES(Bytes(b'').zfill(8)).encrypt(self.plaintext) for half in lm_hash.chunk(8)]


    @RUNTIME.report
    def crack(self, lm_hash: bytes, charset: bytes=None) -> Bytes:
        """
        Cracks both halves simultaneously.

        Parameters:
            lm_hash (bytes): Hash to crack.
            charset (bytes): Character set to use.
        
        Returns:
            Bytes: Cracked LM hash.
        """
        h1, h2 = lm_hash.zfill(16).chunk(8)

        h1_pt, h2_pt = None, None

        h1_null, h2_null = self.check_halves_null(lm_hash)

        if h1_null:
            h1_pt = Bytes(b'').zfill(8)

        if h2_null:
            h2_pt = Bytes(b'').zfill(8)

        if not charset:
            charset = bytes(string.ascii_uppercase + string.digits + string.punctuation, 'utf-8')

        try:
            for i in RUNTIME.report_progress(range(1, 8), unit='length'):
                for attempt in itertools.product(charset, repeat=i):
                    b_attempt = bytes(attempt)
                    hashed    = self.hash(b_attempt)[:8]
                    if hashed == h1:
                        h1_pt = b_attempt

                    if hashed == h2:
                        h2_pt = b_attempt

                    if h1_pt and h2_pt:
                        raise KeyboardInterrupt()

        except KeyboardInterrupt:
            return Bytes(h1_pt or b'\x00').pad_congruent_right(7) + Bytes(h2_pt or b'')
