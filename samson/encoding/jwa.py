from samson.macs.hmac import HMAC
from samson.hashes.sha2 import SHA2, SHA256, SHA384, SHA512
from samson.public_key.ecdsa import ECDSA
from samson.protocols.pkcs1v15_rsa_signer import PKCS1v15RSASigner
from samson.utilities.bytes import Bytes
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
    def __init__(self, hash_obj: SHA2, curve: Curve):
        self.hash_obj = hash_obj
        self.curve = curve
        self.sig_len = (self.curve.q.bit_length() + 7) // 8


    def sign(self, key: bytes, data: bytes) -> Bytes:
        return b''.join([Bytes(part).zfill(self.sig_len) for part in ECDSA(hash_obj=self.hash_obj, G=self.curve.G, d=key).sign(data)])


    def verify(self, key: bytes, data: bytes, sig: bytes) -> bool:
        sig = [val.int() for val in Bytes.wrap(sig).chunk(self.sig_len)]
        return ECDSA(hash_obj=self.hash_obj, G=self.curve.G, d=key).verify(data, sig)



class JWA_RS(object):
    def __init__(self, hash_obj: SHA2):
        self.hash_obj = hash_obj


    def sign(self, key: object, data: bytes) -> Bytes:
        return PKCS1v15RSASigner(rsa=key, hash_obj=self.hash_obj).sign(data)


    def verify(self, key: object, data: bytes, sig: bytes) -> bool:
        return PKCS1v15RSASigner(rsa=key, hash_obj=self.hash_obj).verify(data, sig)



class JWA(Enum):
    HS256 = 'HS256'
    HS384 = 'HS384'
    HS512 = 'HS512'
    ES256 = 'ES256'
    ES384 = 'ES384'
    ES512 = 'ES512'
    RS256 = 'RS256'
    RS384 = 'RS384'
    RS512 = 'RS512'


JWA_ALG_MAP = {
    JWA.HS256: JWA_HS(SHA256()),
    JWA.HS384: JWA_HS(SHA384()),
    JWA.HS512: JWA_HS(SHA512()),
    JWA.ES256: JWA_ES(SHA256(), P256),
    JWA.ES384: JWA_ES(SHA384(), P384),
    JWA.ES512: JWA_ES(SHA512(), P521),
    JWA.RS256: JWA_RS(SHA256()),
    JWA.RS384: JWA_RS(SHA384()),
    JWA.RS512: JWA_RS(SHA512())
}
