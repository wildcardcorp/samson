from samson.encoding.openssh.core.packed_bytes import PackedBytes
from samson.encoding.openssh.core.literal import Literal
from samson.encoding.openssh.general import check_decrypt
from samson.utilities.bytes import Bytes
from samson.padding.incremental_padding import IncrementalPadding
from types import FunctionType

class RSAPrivateKey(object):
    """
    OpenSSH encoding for an RSA private key.
    """

    def __init__(self, name: str, check_bytes: bytes=None, n: int=None, e: int=None, d: int=None, q_mod_p: int=None, p: int=None, q: int=None, host: bytes=None):
        """
        Parameters:
            name          (str): Name for bookkeeping purposes.
            check_bytes (bytes): Four random bytes repeated for OpenSSH to check if the decryption worked.
            n             (int): RSA modulus.
            e             (int): RSA public exponent.
            q_mod_p       (int): RSA q^{-1} mod p.
            p             (int): RSA secret prime.
            q             (int): RSA secret prime.
            host        (bytes): Host the key was generated on.
        """
        self.name = name
        self.check_bytes = check_bytes or Bytes.random(4) * 2
        self.n = n
        self.e = e
        self.d = d
        self.q_mod_p = q_mod_p
        self.p = p
        self.q = q
        self.host = host


    def __repr__(self):
        return f"<RSAPrivateKey: name={self.name}, n={self.n}, e={self.e}, d={self.d}, q_mod_p={self.q_mod_p}, p={self.p}, q={self.q}, host={self.host}>"

    def __str__(self):
        return self.__repr__()


    @staticmethod
    def pack(value: 'RSAPrivateKey', encryptor: FunctionType=None, padding_size: int=8) -> Bytes:
        """
        Packs a private key into an OpenSSH-compliant encoding.

        Parameters:
            value (RSAPrivateKey): Value to encode.
            encryptor      (func): (Optional) Function to use as the encryptor.
            padding_size    (int): The block size to pad to. Usually 8 unless you're encrypting.
        
        Returns:
            Bytes: Packed bytes.
        """
        check_bytes = Literal('check_bytes', length=8).pack(value.check_bytes)
        header = PackedBytes('rsa-header').pack(b'ssh-rsa')
        n = PackedBytes('n').pack(value.n)
        e = PackedBytes('e').pack(value.e)
        d = PackedBytes('d').pack(value.d)
        q_mod_p = PackedBytes('q_mod_p').pack(value.q_mod_p)
        p = PackedBytes('p').pack(value.p)
        q = PackedBytes('q').pack(value.q)
        host = PackedBytes('host').pack(value.host)

        padder = IncrementalPadding(padding_size)
        body = padder.pad(check_bytes + header + n + e + d + q_mod_p + p + q + host)

        if encryptor:
            body = encryptor(body)

        return PackedBytes('private_key').pack(body)


    @staticmethod
    def unpack(encoded_bytes: bytes, decryptor: FunctionType=None) -> ('RSAPrivateKey', bytes):
        """
        Unpacks bytes into an RSAPrivateKey object.

        Parameters:
            encoded_bytes (bytes): Bytes to be (partially?) decoded.
            decryptor      (func): (Optional) Function to use as the decryptor.
        
        Returns:
            (RSAPrivateKey, bytes): The decoded object and unused bytes.
        """
        params, encoded_bytes = PackedBytes('private_key').unpack(encoded_bytes)

        check_bytes, params = check_decrypt(params, decryptor)

        _header, params = PackedBytes('rsa-header').unpack(params)
        n, params = PackedBytes('n').unpack(params)
        e, params = PackedBytes('e').unpack(params)
        d, params = PackedBytes('d').unpack(params)
        q_mod_p, params = PackedBytes('q_mod_p').unpack(params)
        p, params = PackedBytes('p').unpack(params)
        q, params = PackedBytes('q').unpack(params)
        host, params = PackedBytes('host').unpack(params)

        return RSAPrivateKey('private_key', check_bytes=check_bytes, n=n.int(), e=e.int(), d=d.int(), q_mod_p=q_mod_p.int(), p=p.int(), q=q.int(), host=host), encoded_bytes
