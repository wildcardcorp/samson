from samson.math.algebra.curves.weierstrass_curve import WeierstrassCurve, WeierstrassPoint
from samson.utilities.bytes import Bytes
from samson.math.general import mod_inv
from samson.utilities.runtime import RUNTIME
import random

class DualEC(object):
    """
    Implementation of the NSA's backdoored DRBG.
    """

    def __init__(self, P: WeierstrassPoint, Q: WeierstrassPoint, seed: int):
        """
        Parameters:
            P (WeierstrassPoint): Elliptical curve point `P`.
            Q (WeierstrassPoint): Elliptical curve point `Q`.
            seed           (int): Initial value.
        """
        self.P = P
        self.Q = Q
        self.t = seed
        self.r = None


    def __repr__(self):
        return f"<DualEC: P={self.P}, Q={self.Q}, t={self.t}>"

    def __str__(self):
        return self.__repr__()


    def generate(self) -> Bytes:
        """
        Generates the next pseudorandom output.

        Returns:
            int: Next pseudorandom output.
        """
        s = int((self.t * self.P).x)
        self.t = s
        self.r = int((s * self.Q).x)

        return Bytes(int.to_bytes(self.r, 32, 'big')).zfill(32)[2:]


    @staticmethod
    def generate_backdoor(curve: WeierstrassCurve) -> (WeierstrassPoint, WeierstrassPoint, int):
        """
        Generates backdoored parameters.

        Parameters:
            curve (WeierstrassCurve): Curve to use.
        
        Returns:
            (WeierstrassPoint, WeierstrassPoint, int): Result formatted as (P, backdoored Q, backdoor d)
        """
        P = curve.G
        d = random.randint(2, curve.q)
        e = mod_inv(d, curve.q)
        Q = e * P

        return P, Q, d


    @classmethod
    @RUNTIME.report
    def derive_from_backdoor(cls: object, P: WeierstrassPoint, Q: WeierstrassPoint, d: int, observed_out: bytes) -> list:
        """
        Recovers the internal state of a Dual EC generator and builds a replica.

        Parameters:
            P (WeierstrassPoint): Elliptical curve point `P`.
            Q (WeierstrassPoint): Elliptical curve point `Q`.
            d              (int): Backdoor that relates Q to P.
            observed_out (bytes): Observed output from the compromised Dual EC generator.

        Returns:
            list: List of possible internal states.
        """
        assert len(observed_out) >= 30

        curve = P.curve

        r1 = observed_out[:30]
        r2 = observed_out[30:]

        possible_states = []
        Q_cache         = Q.cache_mul(curve.cardinality().bit_length())

        for i in RUNTIME.report_progress(range(2**16), desc='Statespace searched', unit='states'):
            test_r1 = int.to_bytes(i, 2, 'big') + r1
            test_x  = int.from_bytes(test_r1, 'big')
            try:
                R  = curve(test_x)
                dR = d * R
                test_r2 = Q_cache * int(dR.x)

                if int.to_bytes(int(test_r2.x), 32, 'big')[2:2 + len(r2)] == r2:
                    possible_states.append(DualEC(P, Q, int(dR.x)))
            except AssertionError as _:
                pass

        return possible_states
