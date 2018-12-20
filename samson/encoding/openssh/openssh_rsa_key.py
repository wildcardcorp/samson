from samson.encoding.openssh.packed_bytes import PackedBytes
from samson.encoding.openssh.literal import Literal
from samson.encoding.openssh.specification import Specification
from samson.encoding.openssh.kdf_params import KDFParams
from samson.encoding.openssh.rsa_public_key import RSAPublicKey
from samson.encoding.openssh.rsa_private_key import RSAPrivateKey


class OpenSSHRSAKey(Specification):
    SPEC = [
        Literal('header', 15),
        PackedBytes('encryption'),
        PackedBytes('kdf'),
        KDFParams('kdf_params'),
        Literal('num_keys'),
        RSAPublicKey('public_key'),
        RSAPrivateKey('private_key')
    ]

    def __init__(self, header, encryption, kdf, kdf_params, num_keys, public_key, private_key):
        self.spec = OpenSSHRSAKey.SPEC
        self.header = header
        self.encryption = encryption
        self.kdf = kdf
        self.kdf_params = kdf_params
        self.num_keys = num_keys
        self.public_key = public_key
        self.private_key = private_key
