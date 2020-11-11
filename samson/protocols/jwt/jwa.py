from samson.macs.hmac import HMAC
from samson.hashes.sha1 import SHA1
from samson.hashes.sha2 import SHA2, SHA256, SHA384, SHA512
from samson.protocols.pkcs1v15_rsa_signer import PKCS1v15RSASigner
from samson.protocols.ecdhe import ECDHE
from samson.padding.oaep import OAEP
from samson.padding.pkcs1v15_padding import PKCS1v15Padding
from samson.padding.pss import PSS, MGF1
from samson.public_key.ecdsa import ECDSA
from samson.kdfs.concatkdf import ConcatKDF
from samson.utilities.bytes import Bytes
from samson.utilities.exceptions import InvalidMACException
from samson.encoding.general import url_b64_encode, url_b64_decode, PKIEncoding
from samson.encoding.jwk.jwk_eddsa_public_key import JWKEdDSAPublicKey
from samson.block_ciphers.rijndael import Rijndael
from samson.block_ciphers.modes.cbc import CBC
from samson.block_ciphers.modes.gcm import GCM
from samson.block_ciphers.modes.kw import KW
from samson.math.algebra.curves.named import P256, P384, P521
from samson.math.algebra.curves.weierstrass_curve import WeierstrassCurve
from samson.utilities.runtime import RUNTIME
from enum import Enum
import hashlib
import json


class JWA_HS(object):
    def __init__(self, hash_obj: SHA2):
        self.hash_obj = hash_obj


    def sign(self, key: bytes, data: bytes) -> Bytes:
        return HMAC(hash_obj=self.hash_obj, key=key).generate(data)


    def verify(self, key: bytes, data: bytes, sig: bytes) -> bool:
        return self.sign(key, data) == sig



class JWA_ES(object):
    def __init__(self, curve: WeierstrassCurve):
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



class JWA_EdDSA(object):
    def sign(self, key: object, data: bytes) -> Bytes:
        return key.sign(data)


    def verify(self, key: object, data: bytes, sig: Bytes) -> bool:
        sig.byteorder = 'little'
        return key.verify(data, sig)



class JWA_none(object):
    def sign(self, key: object, data: bytes) -> Bytes:
        return b''


    def verify(self, key: object, data: bytes, sig: Bytes) -> bool:
        return False



class JWA_ACBC_HS(object):
    def __init__(self, hash_obj: SHA2):
        self.hash_obj   = hash_obj
        self.key_size   = self.hash_obj.digest_size
        self.chunk_size = self.key_size // 2


    def generate_encryption_params(self) -> Bytes:
        return Bytes.random(self.key_size), Bytes.random(16)


    def encrypt_and_auth(self, key: bytes, iv: bytes, plaintext: bytes, auth_data: bytes) -> (Bytes, Bytes):
        mac_key, enc_key = key.chunk(self.chunk_size)

        rij = Rijndael(enc_key)
        cbc = CBC(rij, iv=iv)

        ciphertext = cbc.encrypt(plaintext)
        hmac       = HMAC(mac_key, self.hash_obj).generate(auth_data + iv + ciphertext + Bytes(len(auth_data) * 8).zfill(8))[:self.chunk_size]

        return ciphertext, hmac


    def decrypt(self, key: bytes, iv: bytes, ciphertext: bytes, auth_data: bytes, auth_tag: bytes) -> Bytes:
        mac_key, enc_key = key.chunk(self.chunk_size)

        hmac = HMAC(mac_key, self.hash_obj).generate(auth_data + iv + ciphertext + Bytes(len(auth_data) * 8).zfill(8))[:self.chunk_size]

        if not RUNTIME.compare_bytes(hmac, auth_tag):
            raise InvalidMACException

        rij = Rijndael(enc_key)
        cbc = CBC(rij, iv=iv)

        return cbc.decrypt(ciphertext)



class JWA_AGCM(object):
    def __init__(self, size: int):
        self.key_size = size // 8


    def generate_encryption_params(self) -> Bytes:
        return Bytes.random(self.key_size), Bytes.random(12)


    def encrypt_and_auth(self, key: bytes, iv: bytes, plaintext: bytes, auth_data: bytes) -> (Bytes, Bytes):
        rij = Rijndael(key)
        gcm = GCM(rij)

        ct_and_tag = gcm.encrypt(iv, plaintext, auth_data)

        return ct_and_tag[:-16], ct_and_tag[-16:]


    def decrypt(self, key: bytes, iv: bytes, ciphertext: bytes, auth_data: bytes, auth_tag: bytes) -> Bytes:
        rij = Rijndael(key)
        gcm = GCM(rij)

        return gcm.decrypt(iv, ciphertext + auth_tag, auth_data)



class JWAKeyEncryptionImplementation(object):
    def generate_encryption_params(self) -> dict:
        return {}



class JWA_AKW(JWAKeyEncryptionImplementation):
    def encrypt(self, kek: bytes, cek: bytes, header: dict) -> Bytes:
        rij = Rijndael(kek)
        kw  = KW(rij, iv=KW.RFC3394_IV)

        return kw.encrypt(cek)


    def decrypt(self, kek: bytes, encrypted_key: bytes, header: dict) -> Bytes:
        rij = Rijndael(kek)
        kw  = KW(rij, iv=KW.RFC3394_IV)

        return kw.decrypt(encrypted_key)



class JWA_RSA1_5(JWAKeyEncryptionImplementation):
    def encrypt(self, kek: bytes, cek: bytes, header: dict) -> Bytes:
        padding = PKCS1v15Padding(kek.n.bit_length())
        return Bytes(kek.encrypt(padding.pad(cek)))


    def decrypt(self, kek: bytes, encrypted_key: bytes, header: dict) -> Bytes:
        padding = PKCS1v15Padding(kek.n.bit_length())
        return padding.unpad(kek.decrypt(encrypted_key))



class JWA_RSA_OAEP(JWAKeyEncryptionImplementation):
    def __init__(self, hash_obj: object):
        self.hash_obj = hash_obj
        self.mgf      = lambda x, y: MGF1(x, y, self.hash_obj)


    def encrypt(self, kek: bytes, cek: bytes, header: dict) -> Bytes:
        padding = OAEP(kek.n.bit_length(), mgf=self.mgf, hash_obj=self.hash_obj)
        return Bytes(kek.encrypt(padding.pad(cek)))


    def decrypt(self, kek: bytes, encrypted_key: bytes, header: dict) -> Bytes:
        padding = OAEP(kek.n.bit_length(), mgf=self.mgf, hash_obj=self.hash_obj)
        return padding.unpad(kek.decrypt(encrypted_key))



class JWA_Dir(JWAKeyEncryptionImplementation):
    def encrypt(self, kek: bytes, cek: bytes, header: dict) -> Bytes:
        return b''


    def decrypt(self, kek: bytes, encrypted_key: bytes, header: dict) -> Bytes:
        return kek



class JWA_AGCMKW(JWAKeyEncryptionImplementation):
    def generate_encryption_params(self) -> dict:
        return {'iv': url_b64_encode(Bytes.random(12)).decode()}


    def encrypt(self, kek: bytes, cek: bytes, header: dict) -> Bytes:
        rij = Rijndael(kek)
        gcm = GCM(rij)

        ct_and_tag    = gcm.encrypt(url_b64_decode(header['iv'].encode('utf-8')), cek, b'')
        header['tag'] = url_b64_encode(ct_and_tag[-16:]).decode()

        return ct_and_tag[:-16]


    def decrypt(self, kek: bytes, encrypted_key: bytes, header: dict) -> Bytes:
        rij = Rijndael(kek)
        gcm = GCM(rij)

        return gcm.decrypt(url_b64_decode(header['iv'].encode('utf-8')), encrypted_key + url_b64_decode(header['tag'].encode('utf-8')), b'')



class JWA_PBES2_HS_AKW(JWAKeyEncryptionImplementation):
    def __init__(self, hash_obj: object):
        self.hash_obj           = hash_obj
        self.hash_fn            = lambda key, msg: HMAC(key, self.hash_obj).generate(msg)
        self._underlying_cipher = JWA_AKW()


    def generate_encryption_params(self) -> dict:
        return {'p2s': url_b64_encode(Bytes.random(8)).decode(), 'p2c': 1000}


    def derive_key(self, kek: bytes, header: dict) -> Bytes:
        derived_salt = header['alg'].encode() + b'\x00' + url_b64_decode(header['p2s'].encode('utf-8'))
        # kdf          = PBKDF2(self.hash_fn, self.hash_obj.digest_size // 2, header['p2c'])
        # derived_key  = kdf.derive(kek, derived_salt)
        derived_key = hashlib.pbkdf2_hmac(self.hash_obj().name, kek, derived_salt, header['p2c'], self.hash_obj().digest_size // 2)

        return derived_key


    def encrypt(self, kek: bytes, cek: bytes, header: dict) -> Bytes:
        return self._underlying_cipher.encrypt(self.derive_key(kek, header), cek, header)


    def decrypt(self, kek: bytes, encrypted_key: bytes, header: dict) -> Bytes:
        return self._underlying_cipher.decrypt(self.derive_key(kek, header), encrypted_key, header)



class JWA_ECDH_ES(JWAKeyEncryptionImplementation):
    def __init__(self):
        self.key_alg = 'enc'


    def derive(self, kek: tuple, derived_length: int, header: dict) -> Bytes:
        from samson.encoding.general import PKIAutoParser

        # Support input formats
        # 1) (priv, pub): Allows user to specify their own private key.
        if type(kek) is tuple:
            priv_key, peer_pub = kek

        # 2) priv: Pull 'epk from header. Used in decryption.
        elif 'epk' in header:
            priv_key = kek
            peer_pub = PKIAutoParser.import_key(json.dumps(header['epk']).encode('utf-8')).key

        # 3) pub: Ephemeral private key.
        else:
            priv_key = ECDHE(G=kek.curve.G)
            peer_pub = kek


        # Need to clean up priv and pub keys
        if type(priv_key) is ECDSA:
            priv_key = ECDHE(d=priv_key.d, G=priv_key.G)


        if hasattr(peer_pub, 'Q'):
            peer_pub = peer_pub.Q
        elif hasattr(peer_pub, 'pub'):
            peer_pub = peer_pub.pub


        # Add 'epk' header if not present
        if not 'epk' in header:
            if type(priv_key) in [ECDSA, ECDHE]:
                encoded_key = ECDSA(G=priv_key.G, d=priv_key.d).export_public_key(encoding=PKIEncoding.JWK).encode()
            else:
                encoded_key = JWKEdDSAPublicKey(priv_key).encode()

            header['epk'] = json.loads(encoded_key.decode())


        # Actual key derivation process
        agreement_key = priv_key.derive_key(peer_pub)

        apu = url_b64_decode(header['apu'].encode('utf-8')) if 'apu' in header else b''
        apv = url_b64_decode(header['apv'].encode('utf-8')) if 'apv' in header else b''

        alg_id     = header[self.key_alg].encode('utf-8')
        other_info = b''.join([Bytes(len(item)).zfill(4) + Bytes.wrap(item) for item in [alg_id, apu, apv]]) + Bytes(derived_length * 8).zfill(4)

        kdf = ConcatKDF(SHA256(), derived_length)
        return kdf.derive(agreement_key, other_info)


    def encrypt(self, kek: tuple, cek: bytes, header: dict) -> Bytes:
        return b''


    def decrypt(self, kek: object, encrypted_key: bytes, header: dict) -> Bytes:
        derived_length = JWA_ALG_MAP[JWAContentEncryptionAlg[header['enc'].replace('-', '_')]].key_size
        return self.derive(kek, derived_length, header)



class JWA_ECDH_ES_AKW(JWA_ECDH_ES):
    def __init__(self, key_size: int):
        self.key_size = key_size // 8
        self.key_alg  = 'alg'


    def encrypt(self, kek: tuple, cek: bytes, header: dict) -> Bytes:
        derived_key = self.derive(kek, self.key_size, header)
        kw          = JWA_AKW()
        return kw.encrypt(derived_key, cek, header)


    def decrypt(self, kek: object, encrypted_key: bytes, header: dict) -> Bytes:
        derived_key = self.derive(kek, self.key_size, header)
        kw          = JWA_AKW()
        return kw.decrypt(derived_key, encrypted_key, header)



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
    EdDSA = 'EdDSA'
    none  = 'none'


# https://tools.ietf.org/html/rfc7518#section-4.1
# https://tools.ietf.org/html/rfc8037
class JWAKeyEncryptionAlg(Enum):
    RSA1_5       = 'RSA1_5'
    RSA_OAEP     = 'RSA-OAEP'
    RSA_OAEP_256 = 'RSA-OAEP-256'
    A128KW       = 'A128KW'
    A192KW       = 'A192KW'
    A256KW       = 'A256KW'
    dir          = 'dir'
    A128GCMKW    = 'A128GCMKW'
    A192GCMKW    = 'A192GCMKW'
    A256GCMKW    = 'A256GCMKW'
    ECDH_ES      = 'ECDH-ES'
    ECDH_ES_plus_A128KW = 'ECDH-ES+A128KW'
    ECDH_ES_plus_A192KW = 'ECDH-ES+A192KW'
    ECDH_ES_plus_A256KW = 'ECDH-ES+A256KW'
    PBES2_HS256_plus_A128KW    = 'PBES2-HS256+A128KW'
    PBES2_HS384_plus_A192KW    = 'PBES2-HS384+A192KW'
    PBES2_HS512_plus_A256KW    = 'PBES2-HS512+A256KW'


# https://tools.ietf.org/html/rfc7518#section-5.1
class JWAContentEncryptionAlg(Enum):
    A128CBC_HS256 = 'A128CBC-HS256'
    A192CBC_HS384 = 'A192CBC-HS384'
    A256CBC_HS512 = 'A256CBC-HS512'
    A128GCM       = 'A128GCM'
    A192GCM       = 'A192GCM'
    A256GCM       = 'A256GCM'


JWA_ALG_MAP = {
    # JWS Signature Algorithms
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
    JWASignatureAlg.EdDSA: JWA_EdDSA(),
    JWASignatureAlg.none: JWA_none,

    # JWE Content-Encryption Algorithms
    JWAContentEncryptionAlg.A128CBC_HS256: JWA_ACBC_HS(SHA256()),
    JWAContentEncryptionAlg.A192CBC_HS384: JWA_ACBC_HS(SHA384()),
    JWAContentEncryptionAlg.A256CBC_HS512: JWA_ACBC_HS(SHA512()),
    JWAContentEncryptionAlg.A128GCM: JWA_AGCM(128),
    JWAContentEncryptionAlg.A192GCM: JWA_AGCM(192),
    JWAContentEncryptionAlg.A256GCM: JWA_AGCM(256),

    # JWE Key-Encryption Algorithms
    JWAKeyEncryptionAlg.RSA1_5: JWA_RSA1_5(),
    JWAKeyEncryptionAlg.RSA_OAEP: JWA_RSA_OAEP(SHA1()),
    JWAKeyEncryptionAlg.RSA_OAEP_256: JWA_RSA_OAEP(SHA256()),
    JWAKeyEncryptionAlg.A128KW: JWA_AKW(),
    JWAKeyEncryptionAlg.A192KW: JWA_AKW(),
    JWAKeyEncryptionAlg.A256KW: JWA_AKW(),
    JWAKeyEncryptionAlg.dir: JWA_Dir(),
    JWAKeyEncryptionAlg.ECDH_ES: JWA_ECDH_ES(),
    JWAKeyEncryptionAlg.ECDH_ES_plus_A128KW: JWA_ECDH_ES_AKW(128),
    JWAKeyEncryptionAlg.ECDH_ES_plus_A192KW: JWA_ECDH_ES_AKW(192),
    JWAKeyEncryptionAlg.ECDH_ES_plus_A256KW: JWA_ECDH_ES_AKW(256),
    JWAKeyEncryptionAlg.A128GCMKW: JWA_AGCMKW(),
    JWAKeyEncryptionAlg.A192GCMKW: JWA_AGCMKW(),
    JWAKeyEncryptionAlg.A256GCMKW: JWA_AGCMKW(),
    JWAKeyEncryptionAlg.PBES2_HS256_plus_A128KW: JWA_PBES2_HS_AKW(hashlib.sha256),
    JWAKeyEncryptionAlg.PBES2_HS384_plus_A192KW: JWA_PBES2_HS_AKW(hashlib.sha384),
    JWAKeyEncryptionAlg.PBES2_HS512_plus_A256KW: JWA_PBES2_HS_AKW(hashlib.sha512)
}
