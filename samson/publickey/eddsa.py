from samson.utilities.bytes import Bytes
from samson.publickey.dsa import DSA
from samson.utilities.ecc import EdwardsCurve25519, TwistedEdwardsPoint, TwistedEdwardsCurve
from samson.hashes.sha2 import SHA512
from copy import deepcopy

def bit(h,i):
  return (h[i//8] >> (i%8)) & 1

# https://ed25519.cr.yp.to/python/ed25519.py
class EdDSA(DSA):
    """
    Edwards Curve Digitial Signature Algorithm
    """

    def __init__(self, curve: TwistedEdwardsCurve=EdwardsCurve25519, hash_obj: object=SHA512(), d: int=None, A: TwistedEdwardsPoint=None):
        """
        Parameters:
            curve (TwistedEdwardsCurve): Curve used for calculations.
            hash_obj           (object): Instantiated object with compatible hash interface.
            d                     (int): Private key.
        """
        self.B = curve.B
        self.curve = curve
        self.d = Bytes.wrap(d or max(1, Bytes.random((curve.b + 7) // 8).int() % curve.q))
        self.H = hash_obj

        self.h = hash_obj.hash(self.d)

        self.a = 2**(curve.n) | sum(2**i * bit(self.h, i) for i in range(curve.c, curve.n))
        self.A = A or self.B * self.a



    def __repr__(self):
        return f"<EdDSA: d={self.d}, A={self.A}, curve={self.curve}, H={self.H}>"

    def __str__(self):
        return self.__repr__()
    

    def encode_point(self, P: TwistedEdwardsPoint) -> Bytes:
        """
        Encodes a `TwistedEdwardsPoint` as `Bytes`.

        Parameters:
            P (TwistedEdwardsPoint): Point to encode.
        
        Returns:
            Bytes: `Bytes` encoding.
        """
        x, y = P.x, P.y
        return Bytes(((x & 1) << self.curve.b-1) + ((y << 1) >> 1), 'little').zfill(self.curve.b // 8)
    


    def decode_point(self, in_bytes: Bytes) -> TwistedEdwardsPoint:
        """
        Decodes `Bytes` to a `TwistedEdwardsPoint`.

        Parameters:
            in_bytes (Bytes): `TwistedEdwardsPoint` encoded as `Bytes`.
        
        Returns:
            TwistedEdwardsPoint: Decoded point.
        """
        y_bytes = deepcopy(in_bytes)
        y_bytes[-1] &= 0x7F
        y = y_bytes.int()
        x = self.curve.recover_point_from_y(y).x

        if (x & 1) != bit(in_bytes, self.curve.b-1):
            x = self.curve.q - x
        
        return TwistedEdwardsPoint(x, y, self.curve)
        


    def sign(self, message: bytes) -> (int, int):
        """
        Signs a `message`.

        Parameters:
            message (bytes): Message to sign.
            k         (int): (Optional) Ephemeral key.
        
        Returns:
            (int, int): Signature formatted as (r, s).
        """
        r = self.H.hash(self.curve.magic + self.h[self.curve.b//8:] + message)[::-1].int()
        R = self.B * (r % self.curve.l)
        eR = self.encode_point(R)
        k = self.H.hash(self.curve.magic + eR + self.encode_point(self.A) + message)[::-1].int()
        S = (r + (k % self.curve.l) * self.a) % self.curve.l
        return eR + Bytes(S, 'little').zfill(self.curve.b//8)
    
    

    def verify(self, message: bytes, sig: (int, int)) -> bool:
        """
        Verifies a `message` against a `sig`.

        Parameters:
            message  (bytes): Message.
            sig ((int, int)): Signature of `message`.
        
        Returns:
            bool: Whether the signature is valid or not.
        """
        sig = Bytes.wrap(sig, 'little')

        if len(sig) != self.curve.b // 4:
            raise ValueError("`sig` length is wrong.")
        
        R = self.decode_point(sig[:self.curve.b//8])
        S = sig[self.curve.b//8:].int()

        h = self.H.hash(self.curve.magic + self.encode_point(R) + self.encode_point(self.A) + message)[::-1].int()

        return self.B * S == R + (self.A * h)