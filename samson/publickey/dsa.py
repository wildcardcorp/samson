from samson.utilities.math import mod_inv
from samson.utilities.bytes import Bytes
from samson.utilities.encoding import export_der, bytes_to_der_sequence
from base64 import b64decode

class DSA(object):
    """
    Digital Signature Algorithm
    """

    def __init__(self, hash_obj: object, p: int=None, q: int=None, g: int=None, x: int=None):
        """
        Parameters:
            hash_obj (object): Instantiated object with compatible hash interface.
            p           (int): (Optional) Prime modulus.
            q           (int): (Optional) Prime modulus.
            g           (int): (Optional) Generator.
            x           (int): (Optional) Private key.
        """
        self.p = p or 0x800000000000000089E1855218A0E7DAC38136FFAFA72EDA7859F2171E25E65EAC698C1702578B07DC2A1076DA241C76C62D374D8389EA5AEFFD3226A0530CC565F3BF6B50929139EBEAC04F48C3C84AFB796D61E5A4F9A8FDA812AB59494232C7D2B4DEB50AA18EE9E132BFA85AC4374D7F9091ABC3D015EFC871A584471BB1
        self.q = q or 0xF4F47F05794B256174BBA6E9B396A7707E563C5B
        self.g = g or 0x5958C9D3898B224B12672C0B98E06C60DF923CB8BC999D119458FEF538B8FA4046C8DB53039DB620C094C9FA077EF389B5322A559946A71903F990F1F7E0E025E2D7F7CF494AFF1A0470F5B64C36B625A097F1651FE775323556FE00B3608C887892878480E99041BE601A62166CA6894BDD41A7054EC89F756BA9FC95302291
        
        self.x = x or Bytes.random((self.q.bit_length() + 7) // 8).int() % self.q
        self.y = pow(self.g, self.x, self.p)
        self.hash_obj = hash_obj

    

    def __repr__(self):
        return f"<DSA: hash_obj={self.hash_obj}, p={self.p}, q={self.q}, g={self.g}, x={self.x}, y={self.y}>"

    def __str__(self):
        return self.__repr__()
    
    

    def sign(self, message: bytes, k: int=None) -> (int, int):
        """
        Signs a `message`.

        Parameters:
            message (bytes): Message to sign.
            k         (int): (Optional) Ephemeral key.
        
        Returns:
            (int, int): Signature formatted as (r, s).
        """
        k = k or max(1, Bytes.random((self.q.bit_length() + 7) // 8).int() % self.q)
        inv_k = mod_inv(k, self.q)
        r = pow(self.g, k, self.p) % self.q
        s = (inv_k * (self.hash_obj.hash(message) + self.x * r)) % self.q
        return (r, s)
    
    

    def verify(self, message: bytes, sig: (int, int)) -> bool:
        """
        Verifies a `message` against a `sig`.

        Parameters:
            message  (bytes): Message.
            sig ((int, int)): Signature of `message`.
        
        Returns:
            bool: Whether the signature is valid or not.
        """
        (r, s) = sig
        w = mod_inv(s, self.q)
        u_1 = (self.hash_obj.hash(message) * w) % self.q
        u_2 = (r * w) % self.q
        v = (pow(self.g, u_1, self.p) * pow(self.y, u_2, self.p) % self.p) % self.q
        return v == r


    
    # Confirmed works on ECDSA as well
    def derive_k_from_sigs(self, msg_a: bytes, sig_a: (int, int), msg_b: bytes, sig_b: (int, int)) -> int:
        """
        Derives `k` from signatures that share an `r` value.

        Parameters:
            msg_a      (bytes): Message A.
            msg_b      (bytes): Message B.
            sig_a ((int, int)): Signature of `msg_a`.
            sig_b ((int, int)): Signature of `msg_b`.

        Returns:
            int: Derived `k`.
        """
        (r_a, s_a) = sig_a
        (r_b, s_b) = sig_b
        assert r_a == r_b
        
        s = (s_a - s_b) % self.q
        m = (self.hash_obj.hash(msg_a) - self.hash_obj.hash(msg_b)) % self.q
        return mod_inv(s, self.q) * m % self.q
    
    

    # Confirmed works on ECDSA as well
    def derive_x_from_k(self, message: bytes, k: int, sig: (int, int)) -> int:
        """
        Derives `x` from a known `k`.

        Parameters:
            message  (bytes): Message.
            k          (int): `k` used in `message`'s signature.
            sig ((int, int)): Signature of `message`.
        
        Returns:
            int: Derived `x`.
        """
        (r, s) = sig
        return ((s * k) - self.hash_obj.hash(message)) * mod_inv(r, self.q) % self.q



    @staticmethod
    def import_key(buffer: bytes):
        """
        Builds an DSA instance from DER and/or PEM-encoded bytes.

        Parameters:
            buffers (bytes): DER and/or PEM-encoded bytes.
        
        Returns:
            DSA: DSA instance.
        """
        items = bytes_to_der_sequence(buffer)

        if len(items) == 6 and int(items[0]) == 0:
            p, q, g, _y, x = [int(item) for item in items[1:6]]
            y = None
        elif len(items) == 4:
            p, q, g, y = [int(item) for item in items]
            x = 0
        
        dsa = DSA(None, p=p, q=q, g=g, x=x)
        if y:
            dsa.y = y

        return dsa



    def export_private_key(self, encode_pem: bool=True, marker: str='DSA PRIVATE KEY') -> bytes:
        """
        Exports the full DSA instance into DER-encoded bytes.

        Parameters:
            encode_pem (bool): Whether or not to PEM-encode as well.
            marker      (str): Marker to use in PEM formatting (if applicable).
        
        Returns:
            bytes: DER-encoding of DSA instance.
        """
        return export_der([0, self.p, self.q, self.g, self.y, self.x], encode_pem, marker)



    def export_public_key(self, encode_pem: bool=True, marker: str='DSA PUBLIC KEY') -> bytes:
        """
        Exports the only the public parameters of the DSA instance into DER-encoded bytes.

        Parameters:
            encode_pem (bool): Whether or not to PEM-encode as well.
            marker      (str): Marker to use in PEM formatting (if applicable).
        
        Returns:
            bytes: DER-encoding of DSA instance.
        """
        return export_der([self.p, self.q, self.g, self.y], encode_pem, marker)
