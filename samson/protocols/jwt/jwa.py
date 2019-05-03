from samson.macs.hmac import HMAC
from samson.hashes.sha2 import SHA2, SHA256, SHA384, SHA512
from samson.public_key.ecdsa import ECDSA
from samson.protocols.pkcs1v15_rsa_signer import PKCS1v15RSASigner
from samson.padding.pss import PSS, MGF1
from samson.utilities.bytes import Bytes
from samson.block_ciphers.rijndael import Rijndael
from samson.block_ciphers.modes.cbc import CBC
from samson.block_ciphers.modes.gcm import GCM
from samson.block_ciphers.modes.kw import KW
from fastecdsa.curve import P256, P384, P521, Curve
from enum import Enum

class JWA_HS(object):
    def __init__(self, hash_obj: SHA2):
        self.hash_obj = hash_obj


    def sign(self, key: bytes, data: bytes) -> Bytes:
        return HMAC(hash_obj=self.hash_obj, key=key).generate(data)


    def verify(self, key: bytes, data: bytes, sig: bytes) -> bool:
        return self.sign(key, data) == sig



class JWA_ES(object):
    def __init__(self, curve: Curve):
        self.sig_len = (curve.q.bit_length() + 7) // 8


    def sign(self, key: object, data: bytes) -> Bytes:
        return b''.join([Bytes(part).zfill(self.sig_len) for part in key.sign(data)])


    def verify(self, key: object, data: bytes, sig: bytes) -> bool:
        sig = [val.int() for val in Bytes.wrap(sig).chunk(self.sig_len)]
        return key.verify(data, sig)



class JWA_RS(object):
    def __init__(self, hash_obj: SHA2):
        self.hash_obj = hash_obj


    def sign(self, key: object, data: bytes) -> Bytes:
        return PKCS1v15RSASigner(rsa=key, hash_obj=self.hash_obj).sign(data)


    def verify(self, key: object, data: bytes, sig: bytes) -> bool:
        return PKCS1v15RSASigner(rsa=key, hash_obj=self.hash_obj).verify(data, sig)



class JWA_PS(object):
    def __init__(self, hash_obj: SHA2):
        self.hash_obj = hash_obj
        self.mgf      = lambda x, y: MGF1(x, y, self.hash_obj)


    def sign(self, key: object, data: bytes) -> Bytes:
        return key.decrypt(PSS(key.n.bit_length(), mgf=self.mgf, hash_obj=self.hash_obj, salt_len=self.hash_obj.digest_size).sign(data))


    def verify(self, key: object, data: bytes, sig: bytes) -> bool:
        return PSS(key.n.bit_length(), mgf=self.mgf, hash_obj=self.hash_obj, salt_len=self.hash_obj.digest_size).verify(data, key.encrypt(sig))



class JWA_ACBC_HS(object):
    def __init__(self, hash_obj: SHA2):
        self.hash_obj    = hash_obj
        self.native_size = self.hash_obj.digest_size // 2
    

    def generate_encryption_params(self) -> Bytes:
        return Bytes.random(self.native_size * 2), Bytes.random(16)


    def encrypt_and_auth(self, key: bytes, iv: bytes, plaintext: bytes, auth_data: bytes) -> (Bytes, Bytes):
        mac_key, enc_key = key.chunk(self.native_size)

        rij = Rijndael(enc_key)
        cbc = CBC(rij.encrypt, rij.decrypt, iv=iv, block_size=rij.block_size)

        ciphertext = cbc.encrypt(plaintext)
        hmac       = HMAC(mac_key, self.hash_obj).generate(auth_data + iv + ciphertext + Bytes(len(auth_data) * 8).zfill(8))[:self.native_size]

        return ciphertext, hmac


    def decrypt(self, key: object, ciphertext: bytes, iv: bytes, auth_data: bytes, auth_tag: bytes) -> Bytes:
        mac_key, enc_key = key.chunk(self.native_size)

        hmac = HMAC(mac_key, self.hash_obj).generate(auth_data + iv + ciphertext + Bytes(len(auth_data) * 8).zfill(8))[:self.native_size]

        # TODO: Constant time?
        assert hmac == auth_tag

        rij = Rijndael(enc_key)
        cbc = CBC(rij.encrypt, rij.decrypt, iv=iv, block_size=rij.block_size)

        return cbc.decrypt(ciphertext)



class JWA_AGCM(object):
    def __init__(self, size):
        self.native_size = size // 8
    

    def generate_encryption_params(self) -> Bytes:
        return Bytes.random(self.native_size), Bytes.random(12)


    def encrypt_and_auth(self, key: bytes, iv: bytes, plaintext: bytes, auth_data: bytes) -> (Bytes, Bytes):
        rij = Rijndael(key)
        gcm = GCM(rij.encrypt)

        ct_and_tag = gcm.encrypt(iv, plaintext, auth_data)

        return ct_and_tag[:-16], ct_and_tag[-16:]


    def decrypt(self, key: object, ciphertext: bytes, iv: bytes, auth_data: bytes, auth_tag: bytes) -> Bytes:
        rij = Rijndael(key)
        gcm = GCM(rij.encrypt)

        return gcm.decrypt(iv, ciphertext + auth_tag, auth_data)



class JWA_AKW(object):
    def encrypt(self, kek: bytes, cek: bytes) -> Bytes:
        rij = Rijndael(kek)
        kw = KW(rij.encrypt, rij.decrypt, iv=KW.RFC3394_IV, block_size=rij.block_size)

        return kw.encrypt(cek)


    def decrypt(self, kek: bytes, encrypted_cek: bytes) -> bool:
        rij = Rijndael(kek)
        kw = KW(rij.encrypt, rij.decrypt, iv=KW.RFC3394_IV, block_size=rij.block_size)

        return kw.decrypt(encrypted_cek)



# https://tools.ietf.org/html/rfc7518#section-3.1
class JWASignatureAlg(Enum):
    HS256 = 'HS256'
    HS384 = 'HS384'
    HS512 = 'HS512'
    ES256 = 'ES256'
    ES384 = 'ES384'
    ES512 = 'ES512'
    RS256 = 'RS256'
    RS384 = 'RS384'
    RS512 = 'RS512'
    PS256 = 'PS256'
    PS384 = 'PS384'
    PS512 = 'PS512'


# https://tools.ietf.org/html/rfc7518#section-4.1
class JWAKeyEncryptionAlg(Enum):
    RSA1_5       = 'RSA1_5'
    RSA_OAEP     = 'RSA-OAEP'
    RSA_OAEP_256 = 'RSA-OAEP-256'
    A128KW       = 'A128KW'
    A192KW       = 'A192KW'
    A256KW       = 'A256KW'


# https://tools.ietf.org/html/rfc7518#section-5.1
class JWAContentEncryptionAlg(Enum):
    A128CBC_HS256 = 'A128CBC-HS256'
    A192CBC_HS384 = 'A192CBC-HS384'
    A256CBC_HS512 = 'A256CBC-HS512'
    A128GCM       = 'A128GCM'
    A192GCM       = 'A192GCM'
    A256GCM       = 'A256GCM'


JWA_ALG_MAP = {
    JWASignatureAlg.HS256: JWA_HS(SHA256()),
    JWASignatureAlg.HS384: JWA_HS(SHA384()),
    JWASignatureAlg.HS512: JWA_HS(SHA512()),
    JWASignatureAlg.ES256: JWA_ES(P256),
    JWASignatureAlg.ES384: JWA_ES(P384),
    JWASignatureAlg.ES512: JWA_ES(P521),
    JWASignatureAlg.RS256: JWA_RS(SHA256()),
    JWASignatureAlg.RS384: JWA_RS(SHA384()),
    JWASignatureAlg.RS512: JWA_RS(SHA512()),
    JWASignatureAlg.PS256: JWA_PS(SHA256()),
    JWASignatureAlg.PS384: JWA_PS(SHA384()),
    JWASignatureAlg.PS512: JWA_PS(SHA512()),

    JWAContentEncryptionAlg.A128CBC_HS256: JWA_ACBC_HS(SHA256()),
    JWAContentEncryptionAlg.A192CBC_HS384: JWA_ACBC_HS(SHA384()),
    JWAContentEncryptionAlg.A256CBC_HS512: JWA_ACBC_HS(SHA512()),
    JWAContentEncryptionAlg.A128GCM: JWA_AGCM(128),
    JWAContentEncryptionAlg.A192GCM: JWA_AGCM(192),
    JWAContentEncryptionAlg.A256GCM: JWA_AGCM(256),

    JWAKeyEncryptionAlg.A128KW: JWA_AKW(),
    JWAKeyEncryptionAlg.A192KW: JWA_AKW(),
    JWAKeyEncryptionAlg.A256KW: JWA_AKW()
}
