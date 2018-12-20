from samson.encoding.openssh.packed_bytes import PackedBytes
from samson.encoding.openssh.literal import Literal
from samson.encoding.openssh.kdf_params import KDFParams
from samson.encoding.openssh.rsa_public_key import RSAPublicKey
from samson.encoding.openssh.rsa_private_key import RSAPrivateKey
from samson.utilities.bytes import Bytes
from types import FunctionType

from samson.block_ciphers.rijndael import Rijndael
from samson.block_ciphers.modes.ctr import CTR
from samson.kdfs.bcrypt_pbkdf import BcryptPBKDF


def init_aes256_ctr(key_iv):
    key, iv = key_iv[:32], key_iv[32:]
    ctr = CTR(Rijndael(key).encrypt, nonce=b'', block_size=16)
    ctr.counter = iv.int()

    return ctr


def derive_bcrypt_pbkdf(passphrase, rounds, key_size, salt=None):
    kdf = BcryptPBKDF(rounds=rounds)
    return kdf.derive(passphrase, salt, key_size)


KDF_ALGS = {
    'bcrypt': derive_bcrypt_pbkdf
}

ENC_ALGS = {
    'aes256-ctr': (init_aes256_ctr, 48, 16)
}



SPEC = [
    Literal('header', 15),
    PackedBytes('encryption'),
    PackedBytes('kdf'),
    KDFParams('kdf_params'),
    Literal('num_keys'),
    RSAPublicKey('public_key'),
    RSAPrivateKey('private_key')
]

class OpenSSHRSAKey(object):
    """
    Represents a full, private OpenSSH RSA key.
    """

    def __init__(self, header: bytes, encryption: bytes, kdf: bytes, kdf_params: KDFParams, num_keys: int, public_key: RSAPublicKey, private_key: RSAPrivateKey):
        """
        Parameters:
            header              (bytes): Header value to include. Should be b'openssh-v1\x00'
            encryption          (bytes): Encryption algorithm to use.
            kdf                 (bytes): KDF to use.
            kdf_params      (KDFParams): Parameters for the KDF.
            num_keys              (int): Number of keys encoded. Should be 1.
            public_key   (RSAPublicKey): Public key parameters.
            private_key (RSAPrivateKey): Private key parameters.
        """
        self.spec = SPEC
        self.header = header
        self.encryption = encryption
        self.kdf = kdf
        self.kdf_params = kdf_params
        self.num_keys = num_keys
        self.public_key = public_key
        self.private_key = private_key



    def pack(self, passphrase: bytes=None, encryptor: FunctionType=None) -> Bytes:
        """
        Packs a private key into an OpenSSH-compliant encoding.

        Parameters:
            value      (bytes): Value to encode.
            passphrase (bytes): (Optional) Passphrase to the key the KDF. Mutually exclusive with `encryptor`.
            encryptor   (func): (Optional) Function to use as the encryptor.
        
        Returns:
            Bytes: Packed bytes.
        """
        if passphrase and encryptor:
            raise RuntimeError("`passphrase` and `encryptor` can't be specified together. Either let samson encrypt it with the given `passphrase` or create your own `encryptor`.")

        val = Bytes(b'')
        self_dict = self.__dict__

        for item in SPEC[:6]:
            val += item.pack(self_dict[item.name])

        padding_size = 8

        if passphrase:
            enc_func, key_size, padding_size = ENC_ALGS[self.encryption.decode()]
            key_iv = KDF_ALGS[self.kdf.decode()](passphrase, self.kdf_params.rounds, key_size, self.kdf_params.salt)
            encryptor = enc_func(key_iv).encrypt

        val += SPEC[-1].pack(self.private_key, encryptor, padding_size)

        return val



    @staticmethod
    def unpack(encoded_bytes: bytes, passphrase: bytes=None, encryptor: FunctionType=None):
        """
        Unpacks bytes into an OpenSSHRSAKey object.

        Parameters:
            encoded_bytes (bytes): Bytes to be decoded.
            passphrase    (bytes): (Optional) Passphrase to the key the KDF. Mutually exclusive with `encryptor`.
            encryptor      (func): (Optional) Function to use as the encryptor.
        
        Returns:
            OpenSSHRSAKey: The decoded object.
        """
        if passphrase and encryptor:
            raise RuntimeError("`passphrase` and `encryptor` can't be specified together. Either let samson encrypt it with the given `passphrase` or create your own `encryptor`.")

        encoded_bytes = Bytes.wrap(encoded_bytes)

        vals = {}
        for item in SPEC[:6]:
            val, encoded_bytes = item.unpack(encoded_bytes)
            vals[item.name] = val

        if passphrase:
            encryption = vals['encryption'].decode()
            kdf = vals['kdf'].decode()
            kdf_params = vals['kdf_params']

            enc_func, key_size, _padding_size = ENC_ALGS[encryption]
            key_iv = KDF_ALGS[kdf](passphrase, kdf_params.rounds, key_size, kdf_params.salt)
            encryptor = enc_func(key_iv).decrypt

        vals['private_key'], encoded_bytes = SPEC[-1].unpack(encoded_bytes, encryptor)

        return OpenSSHRSAKey(**vals)
