from samson.utilities.ecc import WeierstrassCurve, WeierstrassPoint
from samson.utilities.math import random_int, crt
from samson.utilities.bytes import Bytes
from samson.utilities.runtime import RUNTIME
from samson.oracles.default_oracle import DefaultOracle
from sympy import factorint, GF
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
        2) Bruteforcing the residue configuration. GF(67)(15) may actually be GF(67)(52).

    Conditions:
    * Elliptic Curve Diffie-Hellman is being used
    * The user has access to an oracle that accepts arbitrary public keys and returns the residue
    """

    def __init__(self, oracle: DefaultOracle, curve: WeierstrassCurve):
        """
        Parameters:
            oracle   (DefaultOracle): Oracle that accepts (public_key: int, factor: int) and returns (residue: int).
            curve (WeierstrassCurve): Curve that the victim is using.
        """
        self.oracle = oracle
        self.curve  = curve


    @RUNTIME.report
    def execute(self, public_key: WeierstrassPoint, invalid_curves: List[WeierstrassCurve], max_factor_size: int=2**16) -> int:
        """
        Executes the attack.

        Parameters:
            public_key      (int): ECDH public key to crack.
            invalid_curves (list): List of invalid curves to use in the attack.
            max_factor_size (int): Max factor size to prevent attempting to factor forever.
        
        Returns:
            int: Private key.
        """
        residues = []
        moduli   = []

        total = 1

        # TODO: Generate these curves if the user doesn't specify them
        for inv_curve in invalid_curves:
            # Factor as much as we can
            factors = [r for r,_ in factorint(inv_curve.order, limit=max_factor_size).items() if r > 2 and r < max_factor_size]
            log.debug(f'Found factors: {factors}')

            # Request residues from crafted public keys
            for factor in RUNTIME.report_progress(factors, desc='Sending malicious public keys', unit='factor'):
                if total > self.curve.order:
                    break

                if factor in moduli:
                    continue

                total *= factor

                # Generate a low-order point on the invalid curve
                bad_pub = inv_curve.POINT_AT_INFINITY

                while bad_pub == inv_curve.POINT_AT_INFINITY:
                    point   = inv_curve.random_point()
                    bad_pub = point * (inv_curve.order // factor)

                residue = self.oracle.request(bad_pub, factor)
                residues.append(residue)
                moduli.append(factor)


        # We have to take into account the fact we can end up on the "negative" side of the field
        negations = [(residue, (-GF(modulus)(residue)).val) for residue, modulus in zip(residues, moduli)]

        # Just bruteforce the correct configuration based off of the public key
        for residue_subset in RUNTIME.report_progress(itertools.product(*negations), desc='Bruteforcing residue configuration', unit='residue set', total=2**len(residues)):
            n, r = crt(residue_subset, moduli)
            if n * self.curve.G == public_key:
                break

        return n