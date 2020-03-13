from samson.encoding.openssh.core.packed_bytes import PackedBytes
from samson.encoding.openssh.core.literal import Literal
from samson.encoding.openssh.core.kdf_params import KDFParams
from samson.utilities.bytes import Bytes
from types import FunctionType

from samson.block_ciphers.rijndael import Rijndael
from samson.block_ciphers.modes.ctr import CTR
from samson.kdfs.bcrypt_pbkdf import BcryptPBKDF


def init_aes256_ctr(key_iv):
    key, iv = key_iv[:32], key_iv[32:]
    ctr = CTR(Rijndael(key), nonce=b'')
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
    Literal('num_keys')
]


class OpenSSHPrivateHeader(object):
    """
    Represents a full, private OpenSSH key.
    """

    MAGIC_HEADER = b'openssh-key-v1\x00'

    def __init__(self, header: bytes, encryption: bytes, kdf: bytes, kdf_params: KDFParams, num_keys: int):
        """
        Parameters:
            header          (bytes): Header value to include. Should be b'openssh-v1\x00'
            encryption     (bytes): Encryption algorithm to use.
            kdf            (bytes): KDF to use.
            kdf_params (KDFParams): Parameters for the KDF.
            num_keys         (int): Number of keys encoded. Should be 1.
        """
        self.spec = SPEC
        self.header = header
        self.encryption = encryption
        self.kdf = kdf
        self.kdf_params = kdf_params
        self.num_keys = num_keys


    def __repr__(self):
        return f"<OpenSSHPrivateHeader: header={self.header}, encryption={self.encryption}, kdf={self.kdf}, kdf_params={self.kdf_params}, num_keys={self.num_keys}>"

    def __str__(self):
        return self.__repr__()



    def pack(self) -> Bytes:
        """
        Packs a private key into an OpenSSH-compliant encoding.

        Parameters:
            value (bytes): Value to encode.
        
        Returns:
            Bytes: Packed bytes.
        """
        val = Bytes(b'')
        self_dict = self.__dict__

        for item in SPEC:
            val += item.pack(self_dict[item.name])

        return val



    @staticmethod
    def unpack(encoded_bytes: bytes):
        """
        Unpacks bytes into an OpenSSHPrivateHeader object.

        Parameters:
            encoded_bytes (bytes): Bytes to be decoded.

        Returns:
            OpenSSHPrivateHeader: The decoded object.
        """
        encoded_bytes = Bytes.wrap(encoded_bytes)

        vals = {}
        for item in SPEC:
            val, encoded_bytes = item.unpack(encoded_bytes)
            vals[item.name] = val

        vals['num_keys'] = vals['num_keys'].int()

        return OpenSSHPrivateHeader(**vals), encoded_bytes



    def generate_encryptor(self, passphrase: bytes) -> (FunctionType, int):
        """
        Generates an encryptor based on the KDF parameters and `passphrase`.

        Parameters:
            passphrase (bytes): Passphrase for key derivation.
        
        Returns:
            (func, int): Encryption function and padding size.
        """
        enc_func, key_size, padding_size = ENC_ALGS[self.encryption.decode()]
        key_iv = KDF_ALGS[self.kdf.decode()](passphrase, self.kdf_params.rounds, key_size, self.kdf_params.salt)
        return enc_func(key_iv).encrypt, padding_size


    # TODO: Add more decryption algorithms
    def generate_decryptor(self, passphrase: bytes) -> FunctionType:
        """
        Generates an decryptor based on the KDF parameters and `passphrase`.

        Parameters:
            passphrase (bytes): Passphrase for key derivation.
        
        Returns:
            func: Encryption function.
        """
        return self.generate_encryptor(passphrase)[0]
