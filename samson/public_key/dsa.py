from samson.utilities.math import mod_inv
from samson.utilities.bytes import Bytes
from samson.utilities.encoding import export_der, bytes_to_der_sequence, parse_openssh
from samson.utilities.pem import pem_encode, pem_decode
from samson.hashes.sha2 import SHA256
from pyasn1.codec.der import encoder, decoder
from pyasn1.type.univ import Integer, ObjectIdentifier, BitString, SequenceOf, Sequence
import base64
import math

class DSA(object):
    """
    Digital Signature Algorithm
    """

    def __init__(self, hash_obj: object=SHA256(), p: int=None, q: int=None, g: int=None, x: int=None):
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
    def import_key(buffer: bytes, passphrase: bytes=None):
        """
        Builds an DSA instance from DER and/or PEM-encoded bytes.

        Parameters:
            buffer     (bytes): DER and/or PEM-encoded bytes.
            passphrase (bytes): Passphrase to decrypt DER-bytes (if applicable).
        
        Returns:
            DSA: DSA instance.
        """
        if buffer.startswith(b'----'):
            buffer = pem_decode(buffer, passphrase)

        ssh_header = b'ssh-dss'

        if ssh_header in buffer:
            # SSH public key?
            if buffer.startswith(ssh_header):
                buffer = base64.b64decode(buffer.split(b' ')[1])


            key_parts = parse_openssh(ssh_header, buffer)

            # Public key?
            if len(key_parts) == 5:
                p, q, g, y = [part.int() for part in key_parts[1:]]
                x = 0
            else:
                p, q, g, y, x, _host = [part.int() for part in key_parts[6:]]

        else:
            items = bytes_to_der_sequence(buffer, passphrase)

            if len(items) == 6 and int(items[0]) == 0:
                p, q, g, y, x = [int(item) for item in items[1:6]]

            # Is public key?
            elif len(items) == 2 and str(items[0][0]) == '1.2.840.10040.4.1':
                y_sequence_bytes = Bytes(int(items[1]))
                y = int(decoder.decode(y_sequence_bytes)[0])
                p, q, g = [int(item) for item in items[0][1]]
                x = 0
            else:
                raise ValueError("Unable to parse provided DSA key.")

        dsa = DSA(None, p=p, q=q, g=g, x=x)
        dsa.y = y

        return dsa



    def export_private_key(self, encode_pem: bool=True, marker: str='DSA PRIVATE KEY', encryption: str=None, passphrase: bytes=None, iv: bytes=None) -> bytes:
        """
        Exports the full DSA instance into DER-encoded bytes.

        Parameters:
            encode_pem  (bool): Whether or not to PEM-encode as well.
            marker       (str): Marker to use in PEM formatting (if applicable).
            encryption   (str): (Optional) RFC1423 encryption algorithm (e.g. 'DES-EDE3-CBC').
            passphrase (bytes): (Optional) Passphrase to encrypt DER-bytes (if applicable).
            iv         (bytes): (Optional) IV to use for CBC encryption.
        
        Returns:
            bytes: DER-encoding of DSA instance.
        """
        der = export_der([0, self.p, self.q, self.g, self.y, self.x])

        if encode_pem:
            der = pem_encode(der, marker, encryption=encryption, passphrase=passphrase, iv=iv)

        return der



    def export_public_key(self, encode_pem: bool=True, marker: str='PUBLIC KEY') -> bytes:
        """
        Exports the only the public parameters of the DSA instance into DER-encoded bytes.

        Parameters:
            encode_pem (bool): Whether or not to PEM-encode as well.
            marker      (str): Marker to use in PEM formatting (if applicable).
        
        Returns:
            bytes: DER-encoding of DSA instance.
        """
        seq_of = SequenceOf()
        seq_of.extend([Integer(self.p), Integer(self.q), Integer(self.g)])

        seq = Sequence()
        seq.setComponentByPosition(0, ObjectIdentifier([1, 2, 840, 10040, 4, 1]))
        seq.setComponentByPosition(1, seq_of)

        y_bits = bin(Bytes(encoder.encode(Integer(self.y))).int())[2:]
        y_bits = y_bits.zfill(math.ceil(len(y_bits) / 8) * 8)
        y_bits = BitString(y_bits)

        top_seq = Sequence()
        top_seq.setComponentByPosition(0, seq)
        top_seq.setComponentByPosition(1, y_bits)

        der_encoded = encoder.encode(top_seq)

        if encode_pem:
            der_encoded = pem_encode(der_encoded, marker)

        return der_encoded
