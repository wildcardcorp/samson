from samson.utilities.bytes import Bytes
from samson.hashes.sha1 import SHA1

def MGF1(seed, length):
    seed_int = seed.int()
    mask = b''
    sha1 = SHA1()

    for i in range(seed_int, seed_int + (length + 19) // 20):
        mask += sha1.hash(Bytes(i))
    
    return mask[:length]


# https://www.ietf.org/rfc/rfc3447.txt
class OAEP(object):
    def __init__(self, modulus_len, mgf=MGF1, hash_obj=SHA1(), label=b''):
        self.mgf = mgf
        self.hash_obj = hash_obj
        self.label = label
        self.modulus_len = modulus_len


    def __repr__(self):
        return f"<OAEP: mgf={self.mgf}, hash_obj={self.hash_obj}, label={self.label}>"


    def __str__(self):
        return self.__repr__()

        

    def pad(self, plaintext):
        plaintext = Bytes.wrap(plaintext)
        k = self.modulus_len // 8

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

        seed = Bytes.random(h_len)

        db_mask = self.mgf(seed, k - h_len - 1)
        masked_db = db ^ db_mask

        seed_mask = self.mgf(masked_db, h_len)
        masked_seed = seed ^ seed_mask

        return b'\x00' + masked_seed + masked_db



    def unpad(self, plaintext):
        plaintext = Bytes.wrap(plaintext)
        k = self.modulus_len // 8
        h_len = self.hash_obj.digest_size
        
        masked_seed, masked_db = plaintext[1:(h_len + 1)], plaintext[(h_len + 1):]

        seed_mask = self.mgf(masked_db, h_len)
        seed = masked_seed ^ seed_mask

        db_mask = self.mgf(seed, k - h_len - 1)
        db = masked_db ^ db_mask

        l_hash, m = db[:h_len], db[h_len + db[h_len:].index(b'\x01') + 1:]
        if l_hash != self.hash_obj.hash(self.label):
            return ValueError("Label hashes do not match")

        return m