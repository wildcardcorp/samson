from samson.math.algebra.curves.weierstrass_curve import WeierstrassCurve, WeierstrassPoint
from samson.math.algebra.rings.integer_ring import ZZ
from samson.math.general import crt, factor as factorint
from samson.utilities.runtime import RUNTIME
from samson.oracles.default_oracle import DefaultOracle
from typing import List
import itertools

import logging
log = logging.getLogger(__name__)


class InvalidCurveAttack(object):
    """
    The Invalid Curve attack takes advantage of systems that don't validate whether the other party's public key is on the curve.
    The attacker can generate curves of smoother order with a different `b` constant, and then generate a public key
    that lies inside of a subgroup.

    There are two phases to this attack:
        1) Finding residues modulo the small factors of the group order
        2) Bruteforcing the residue configuration. (ZZ/ZZ(67))(15) may actually be (ZZ/ZZ(67))(52).

    Conditions:
    * Elliptic Curve Diffie-Hellman is being used
    * The user has access to an oracle that accepts arbitrary public keys and returns the residue
    """

    def __init__(self, oracle: DefaultOracle, curve: WeierstrassCurve):
        """
        Parameters:
            oracle   (DefaultOracle): Oracle that accepts (public_key: WeierstrassPoint, factor: int) and returns (residue: int).
            curve (WeierstrassCurve): Curve that the victim is using.
        """
        self.oracle = oracle
        self.curve  = curve


    @RUNTIME.report
    def execute(self, public_key: WeierstrassPoint, invalid_curves: List[WeierstrassCurve]=None, max_factor_size: int=2**16) -> int:
        """
        Executes the attack.

        Parameters:
            public_key      (int): ECDH public key to crack.
            invalid_curves (list): List of invalid curves to use in the attack.
            max_factor_size (int): Max factor size to prevent attempting to factor forever.
        
        Returns:
            int: Private key.
        """
        residues     = []
        factors_seen = set()
        total        = 1

        reached_card = False

        if not invalid_curves:
            invalid_curves = []


        # Generate invalid curves if the user doesn't specify them or have enough factors
        def curve_gen():
            orig = self.curve
            while True:
                b = orig.b

                while b == orig.b:
                    b = orig.ring.random()

                curve = WeierstrassCurve(a=orig.a, b=b, ring=orig.ring)
                curve.cardinality()

                curve.G_cache = orig.G_cache
                yield curve


        for inv_curve in itertools.chain(invalid_curves, curve_gen()):
            # Factor as much as we can
            factors = [r for r,_ in factorint(inv_curve.cardinality(), use_rho=False, limit=max_factor_size).items() if r > 2 and r < max_factor_size]
            log.debug(f'Found factors: {factors}')

            # Request residues from crafted public keys
            for factor in RUNTIME.report_progress(set(factors) - factors_seen, desc='Sending malicious public keys', unit='factor'):
                if total > self.curve.cardinality():
                    reached_card = True
                    break

                if factor in factors_seen:
                    continue

                total *= factor

                # Generate a low-order point on the invalid curve
                bad_pub = inv_curve.POINT_AT_INFINITY

                while bad_pub == inv_curve.POINT_AT_INFINITY:
                    point   = inv_curve.random()
                    bad_pub = point * (inv_curve.cardinality() // factor)

                residue = self.oracle.request(bad_pub, factor)
                residues.append((ZZ/ZZ(factor))(residue))
                factors_seen.add(factor)

            if reached_card:
                break

        # We have to take into account the fact we can end up on the "negative" side of the field
        negations = [(residue, -residue) for residue in residues]

        # Just bruteforce the correct configuration based off of the public key
        for residue_subset in RUNTIME.report_progress(itertools.product(*negations), desc='Bruteforcing residue configuration', unit='residue set', total=2**len(residues)):
            n, _ = crt(residue_subset)
            if int(n) * self.curve.G == public_key:
                break

        return n.val
