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


    def check_halves_null(self, lm_hash: bytes) -> (bool, bool):
        """
        Checks if either half of the plaintext is null. LM hashes encrypt each half of the plaintext separately so
        attackers can determine if the plaintext is less than eight characters by checking if the second half is 'aad3b435b51404ee'.

        Parameters:
            lm_hash (bytes): LM hash.
        
        Returns:
            (bool, bool): Whether or not each half of the LM hash is null.
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
        h1, h2           = lm_hash.zfill(16).chunk(8)
        h1_pt, h2_pt     = None, None
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


    @staticmethod
    def lm_to_ntlm(cracked: bytes, ntlm_hex: bytes) -> Bytes:
        """
        Since LM hashes uppercase all letters, the password may not match the password for the NTLM hash.
        By trying every combination of uppercase and lowercase, the NTLM hash can be bruteforced.

        Parameters:
            cracked  (bytes): Cracked password of LM hash.
            ntlm_hex (bytes): Target NTLM hash in hex format.

        Returns:
            Bytes: The NTLM hash's password.
        """
        from samson.hashes.ntlm import NTLM
        import string
        import itertools

        letters      = [(idx, chr(l)) for idx, l in enumerate(cracked) if chr(l) in string.ascii_uppercase]
        both_cases   = [(l, l.lower()) for _idx, l in letters]
        cracked_copy = bytearray(cracked)
        ntlm         = NTLM()

        for prod in itertools.product(*both_cases):
            for c, (i, _) in zip(prod, letters):
                cracked_copy[i] = ord(c)

            if ntlm.hash(cracked_copy).hex() == ntlm_hex:
                return Bytes(cracked_copy)


    @staticmethod
    def reconstruct_from_sam(hashcat_lm_list: bytes, sam_ntlm_list: bytes) -> dict:
        """
        Given a list of hashcat-formatted, cracked LM halves (<LM>:<PLAINTEXT>) and a list
        of SAM accounts (<USERNAME>:<RID>:<LM>:<NTLM>), this function reconstructs the plaintext
        passwords with casing.

        Parameters:
            hashcat_lm_list (bytes): List or newline-delimited bytes of hashcat LM halves.
            sam_ntlm_list   (bytes): List or newline-delimited bytes of SAM accounts.

        Returns:
            dict: Dictionary of {`username`: `password`}.
        """
        if type(hashcat_lm_list) is bytes:
            hashcat_lm_list = hashcat_lm_list.strip().split(b'\n')

        if type(sam_ntlm_list) is bytes:
            sam_ntlm_list = sam_ntlm_list.strip().split(b'\n')

        lookup_table = {}
        for kv in hashcat_lm_list:
            k,v = kv.split(b':')
            lookup_table[k] = v

        lookup_table[b'aad3b435b51404ee'] = b''

        sam_list = [sam_entry.split(b':') for sam_entry in sam_ntlm_list]

        cracked = {}
        for sam in sam_list:
            try:
                username = sam[0]
                lm       = sam[2]
                ntlm     = sam[3]

                h0, h1   = lm[:16], lm[16:]
                lm_pass  = lookup_table[h0] + lookup_table[h1]

                if lm_pass:
                    password = LM.lm_to_ntlm(lm_pass, ntlm)
                    cracked[username] = password
            except KeyError:
                pass

        return cracked
