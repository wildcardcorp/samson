from samson.utilities.math import mod_inv
from samson.utilities.manipulation import get_blocks
from samson.utilities.bytes import Bytes
from samson.publickey.dsa import DSA
from samson.utilities.encoding import export_der, bytes_to_der_sequence, oid_tuple_to_bytes
from pyasn1.type.univ import Integer, OctetString, ObjectIdentifier, BitString
from pyasn1.codec.ber import decoder as ber_decoder, encoder as ber_encoder
from fastecdsa.point import Point
from fastecdsa.curve import Curve
import math


# https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
class ECDSA(DSA):
    """
    Elliptical Curve Digital Signature Algorithm
    """

    def __init__(self, G: Point, hash_obj: object, d: int=None):
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
    def import_key(buffer: bytes):
        """
        Builds an ECDSA instance from DER and/or PEM-encoded bytes.

        Parameters:
            buffers (bytes): DER and/or PEM-encoded bytes.
        
        Returns:
            ECDSA: ECDSA instance.
        """
        items = bytes_to_der_sequence(buffer)

        if len(items) == 4 and int(items[0]) == 1:
            d = Bytes(items[1]).int()

            curve_oid = items[2].asTuple()
            oid_bytes = ber_encoder.encode(ObjectIdentifier(curve_oid))[2:]
            curve = Curve.get_curve_by_oid(oid_bytes)

            x_y_bytes = Bytes(int(items[3]))[1:]
            x, y = x_y_bytes[:len(x_y_bytes) // 2].int(), x_y_bytes[len(x_y_bytes) // 2:].int()
        
        return ECDSA(G=Point(x, y, curve), hash_obj=None, d=d)



    def export_private_key(self, encode_pem: bool=True, marker: str='EC PRIVATE KEY') -> bytes:
        """
        Exports the full ECDSA instance into DER-encoded bytes.

        Parameters:
            encode_pem (bool): Whether or not to PEM-encode as well.
            marker      (str): Marker to use in PEM formatting (if applicable).
        
        Returns:
            bytes: DER-encoding of DSA instance.
        """
        return export_der([1, Bytes(self.d), ber_decoder.decode(b'\x06' + bytes([len(self.G.curve.oid)]) + self.G.curve.oid)[0].asTuple(), (b'\x00\x04' + Bytes(self.G.x) + Bytes(self.G.y)).int()], encode_pem, marker, item_types=[Integer, OctetString, ObjectIdentifier, BitString])
    


    def export_public_key(self, encode_pem: bool=True, marker: str='EC PUBLIC KEY') -> bytes:
        """
        Exports the only the public parameters of the ECDSA instance into DER-encoded bytes.

        Parameters:
            encode_pem (bool): Whether or not to PEM-encode as well.
            marker      (str): Marker to use in PEM formatting (if applicable).
        
        Returns:
            bytes: DER-encoding of ECDSA instance.
        """
        raise NotImplementedError()