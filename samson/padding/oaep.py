from samson.utilities.bytes import Bytes
from samson.hashes.sha1 import SHA1
from types import FunctionType

def MGF1(seed: bytes, length: int) -> Bytes:
    """
    Peforms the mask generation function v1 from RFC3447 B.2.1.

    Parameters:
        seed (bytes): Initial value.
        length (int): Length of mask to produce.
    
    Returns:
        Bytes: Mask.
    """
    mask = b''
    sha1 = SHA1()

    for i in range((length + 19) // 20):
        mask += sha1.hash(seed + Bytes(i).zfill(4))

    return mask[:length]


# https://www.ietf.org/rfc/rfc3447.txt
class OAEP(object):
    """
    Optimal Asymmetric Encryption Padding

    Probablistic Feistel Network proven to be semantically secure under chosen plaintext attack.
    """

    def __init__(self, modulus_len: int, mgf: FunctionType=MGF1, hash_obj: object=SHA1(), label: bytes=b''):
        """
        Parameters:
            modulus_len (int): Length of the RSA modulus, i.e. RSA bit strength.
            mgf        (func): Mask generation function. Takes in `seed` and `length` and returns bytes.
            hash_obj (object): Instantiated object with compatible hash interface.
            label     (bytes): (Optional) 
        """
        self.mgf = mgf
        self.hash_obj = hash_obj
        self.label = label
        self.modulus_len = modulus_len


    def __repr__(self):
        return f"<OAEP: mgf={self.mgf}, hash_obj={self.hash_obj}, label={self.label}>"

    def __str__(self):
        return self.__repr__()



    def pad(self, plaintext: bytes, seed: bytes=None) -> Bytes:
        """
        Pads the `plaintext`.

        Parameters:
            plaintext (bytes): Plaintext to pad.
            seed      (bytes): (Optional) Random seed for the MGF.
        
        Returns:
            Bytes: Padded plaintext.
        """
        plaintext = Bytes.wrap(plaintext)
        k = (self.modulus_len + 7) // 8

        # Step 1: Length checking
        h_len = self.hash_obj.digest_size
        m_len = len(plaintext)
        ps_len = k - m_len - (2 * h_len) - 2

        if ps_len < 0:
            raise ValueError("Plaintext is too long")


        # Step 2: EME-OAEP encoding
        l_hash = self.hash_obj.hash(self.label)

        ps = Bytes(b'').zfill(ps_len)
        db = l_hash + ps + b'\x01' + plaintext

        seed = seed or Bytes.random(h_len)

        db_mask = self.mgf(seed, k - h_len - 1)
        masked_db = db ^ db_mask

        seed_mask = self.mgf(masked_db, h_len)
        masked_seed = seed ^ seed_mask

        return b'\x00' + masked_seed + masked_db



    def unpad(self, plaintext: bytes, allow_mangers: bool=False, skip_label_check: bool=False) -> Bytes:
        """
        Unpads the `plaintext`.

        Parameters:
            plaintext         (bytes): Plaintext to pad.
            allow_mangers      (bool): Whether or not to explicitly help Manger's attack.
            skip_label_check   (bool): Whether or not to skip checking the label.
        
        Returns:
            Bytes: Unpadded plaintext.
        """
        k = (self.modulus_len + 7) // 8
        h_len = self.hash_obj.digest_size
        plaintext = Bytes.wrap(plaintext).zfill(k)

        if allow_mangers:
            if plaintext[0] != 0:
                raise ValueError("First byte is not zero! ;)")

        masked_seed, masked_db = plaintext[1:(h_len + 1)], plaintext[(h_len + 1):]

        seed_mask = self.mgf(masked_db, h_len)
        seed = masked_seed ^ seed_mask

        db_mask = self.mgf(seed, k - h_len - 1)
        db = masked_db ^ db_mask

        l_hash, m = db[:h_len], db[h_len + db[h_len:].index(b'\x01') + 1:]
        if not skip_label_check and l_hash != self.hash_obj.hash(self.label):
            raise ValueError("Label hashes do not match")

        return m
