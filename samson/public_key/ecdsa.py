from fastecdsa.curve import P192, P224, P256, P384, P521
from samson.utilities.math import mod_inv
from samson.utilities.bytes import Bytes
from samson.public_key.dsa import DSA
from samson.hashes.sha2 import SHA256
from samson.utilities.encoding import export_der, bytes_to_der_sequence, parse_openssh
from samson.utilities.pem import pem_encode, pem_decode
from pyasn1.type.univ import Integer, OctetString, ObjectIdentifier, BitString, SequenceOf, tag
from pyasn1.codec.ber import decoder as ber_decoder, encoder as ber_encoder
from fastecdsa.point import Point
from fastecdsa.curve import Curve
import math
import base64

class NamedCurve(ObjectIdentifier):
    tagSet = baseTagSet = tag.initTagSet(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 6)
    ).tagExplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))

    typeId = ObjectIdentifier.typeId



class PublicPoint(BitString):
    tagSet = baseTagSet = tag.initTagSet(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 3)
    ).tagExplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))

    typeId = BitString.typeId



# https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
class ECDSA(DSA):
    """
    Elliptical Curve Digital Signature Algorithm
    """

    def __init__(self, G: Point, hash_obj: object=SHA256(), d: int=None):
        """
        Parameters:
            G         (Point): Generator point for a curve.
            hash_obj (object): Instantiated object with compatible hash interface.
            d           (int): (Optional) Private key.
        """
        self.G = G
        self.q = self.G.curve.q
        self.d = d or max(1, Bytes.random(self.q.bit_length() + 7 // 8).int() % self.q)
        self.Q = self.d * self.G
        self.hash_obj = hash_obj



    def __repr__(self):
        return f"<ECDSA: d={self.d}, G={self.G}, Q={self.Q}, hash_obj={self.hash_obj}>"

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
        r = 0
        s = 0

        while s == 0 or r == 0:
            k = k or max(1, Bytes.random(self.q .bit_length() + 7 // 8).int() % self.q)
            inv_k = mod_inv(k, self.q)

            z = self.hash_obj.hash(message).int()
            z >>= max(self.hash_obj.digest_size * 8 - self.q.bit_length(), 0)

            r = (k * self.G).x % self.q
            s = (inv_k * (z + self.d * r)) % self.q

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

        z = self.hash_obj.hash(message).int()
        z >>= max(self.hash_obj.digest_size * 8 - self.q.bit_length(), 0)

        u_1 = (z * w) % self.q
        u_2 = (r * w) % self.q
        v = u_1 * self.G + u_2 * self.Q
        return v.x == r



    # https://tools.ietf.org/html/rfc5656
    # https://github.com/golang/crypto/blob/master/ssh/keys.go
    # https://stackoverflow.com/questions/5929050/how-does-asn-1-encode-an-object-identifier
    @staticmethod
    def import_key(buffer: bytes, passphrase: bytes=None):
        """
        Builds an ECDSA instance from DER and/or PEM-encoded bytes.

        Parameters:
            buffer     (bytes): DER and/or PEM-encoded bytes.
            passphrase (bytes): Passphrase to decrypt DER-bytes (if applicable).
        
        Returns:
            ECDSA: ECDSA instance.
        """
        if buffer.startswith(b'----'):
            buffer = pem_decode(buffer, passphrase)

        ssh_header = b'ecdsa-'

        if ssh_header in buffer:
            # SSH public key?
            if buffer.startswith(ssh_header):
                buffer = base64.b64decode(buffer.split(b' ')[1])

            key_parts = parse_openssh(ssh_header, buffer)

            # Public key?
            if len(key_parts) == 3:
                curve, x_y_bytes = key_parts[1:]
                d = 1
            else:
                curve, x_y_bytes, d, _host, _ = key_parts[4:]
                d = d.int()

            if curve == b'nistp192':
                curve = P192
            elif curve == b'nistp224':
                curve = P224
            elif curve == b'nistp256':
                curve = P256
            elif curve == b'nistp384':
                curve = P384
            elif curve == b'nistp521':
                curve = P521

        else:
            items = bytes_to_der_sequence(buffer, passphrase)

            if len(items) == 4 and int(items[0]) == 1:
                d = Bytes(items[1]).int()
                curve_idx = 2
                pub_point_idx = 3


            # Is it a public key?
            elif len(items) == 2 and str(items[0][0]) == '1.2.840.10045.2.1':
                curve_idx = 0
                pub_point_idx = 1
                d = 1

                # Move up OID for convenience
                items[0] = items[0][1]
            else:
                raise ValueError("Unable to parse provided ECDSA key.")


            curve_oid = items[curve_idx].asTuple()
            oid_bytes = ber_encoder.encode(ObjectIdentifier(curve_oid))[2:]
            curve = Curve.get_curve_by_oid(oid_bytes)

            x_y_bytes = Bytes(int(items[pub_point_idx]))


        # Uncompressed Point
        if x_y_bytes[0] == 4:
            x_y_bytes = x_y_bytes[1:]
        else:
            raise NotImplementedError("Support for ECPoint decompression not implemented.")

        x, y = x_y_bytes[:len(x_y_bytes) // 2].int(), x_y_bytes[len(x_y_bytes) // 2:].int()
        Q = Point(x, y, curve)

        ecdsa = ECDSA(G=curve.G, hash_obj=None, d=d)
        ecdsa.Q = Q

        return ecdsa



    def format_public_point(self) -> str:
        """
        Internal function used for exporting the key. Formats `Q` into a bitstring.
        """
        zero_fill = math.ceil(self.G.curve.q.bit_length() / 8)
        pub_point_bs = bin((b'\x00\x04' + (Bytes(self.Q.x).zfill(zero_fill) + Bytes(self.Q.y).zfill(zero_fill))).int())[2:]
        pub_point_bs = pub_point_bs.zfill(math.ceil(len(pub_point_bs) / 8) * 8)
        return pub_point_bs



    def export_private_key(self, encode_pem: bool=True, marker: str='EC PRIVATE KEY', encryption: str=None, passphrase: bytes=None, iv: bytes=None) -> bytes:
        """
        Exports the full ECDSA instance into DER-encoded bytes.

        Parameters:
            encode_pem (bool): Whether or not to PEM-encode as well.
            marker      (str): Marker to use in PEM formatting (if applicable).
            encryption   (str): (Optional) RFC1423 encryption algorithm (e.g. 'DES-EDE3-CBC').
            passphrase (bytes): (Optional) Passphrase to encrypt DER-bytes (if applicable).
            iv         (bytes): (Optional) IV to use for CBC encryption.
        
        Returns:
            bytes: DER-encoding of DSA instance.
        """
        zero_fill = math.ceil(self.G.curve.q.bit_length() / 8)
        der = export_der([1, Bytes(self.d).zfill(zero_fill), ber_decoder.decode(b'\x06' + bytes([len(self.G.curve.oid)]) + self.G.curve.oid)[0].asTuple(), self.format_public_point()], item_types=[Integer, OctetString, NamedCurve, PublicPoint])

        if encode_pem:
            der = pem_encode(der, marker, encryption=encryption, passphrase=passphrase, iv=iv)

        return der



    def export_public_key(self, encode_pem: bool=True, marker: str='PUBLIC KEY') -> bytes:
        """
        Exports the only the public parameters of the ECDSA instance into DER-encoded bytes.

        Parameters:
            encode_pem (bool): Whether or not to PEM-encode as well.
            marker      (str): Marker to use in PEM formatting (if applicable).
        
        Returns:
            bytes: DER-encoding of ECDSA instance.
        """
        curve_seq = [ObjectIdentifier([1, 2, 840, 10045, 2, 1]), ObjectIdentifier(ber_decoder.decode(b'\x06' + bytes([len(self.G.curve.oid)]) + self.G.curve.oid)[0].asTuple())]
        der = export_der([curve_seq, self.format_public_point()], item_types=[SequenceOf, BitString])

        if encode_pem:
            der = pem_encode(der, marker)

        return der
