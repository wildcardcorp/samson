from samson.math.algebra.curves.weierstrass_curve import WeierstrassCurve, WeierstrassPoint
from samson.math.algebra.curves.named import _PRECOMPUTED_ICA_PLANS, _PRECOMPUTED_ICA_ORDERS
from samson.math.general import crt, product, lcm, bsgs, kth_root
from samson.math.factorization.general import factor
from samson.protocols.ecdhe import ECDHE
from samson.utilities.runtime import RUNTIME
from samson.utilities.exceptions import SearchspaceExhaustedException
from typing import List

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
        residues = []

        # Reaching cardinality only determines the key up to sign.
        # By getting to cardinality squared, we can get the exact key
        # without having to do a lengthy bruteforce
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

                # Two is a special case, and we require an exponent of at least 3.
                if fac == 2 and exponent < 3:
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


        # Display plan stats
        avg_requests = 0
        needed_res   = 0
        for curve, fac, exponent in final_plan:
            avg_requests += ((fac+1) // 2)*exponent
            needed_res   += exponent

        log.debug(f'Attack plan consists of {needed_res} residues and an average of {avg_requests} oracle requests')


        # Execute the attack
        @RUNTIME.threaded(threads=self.threads, starmap=True)
        def find_residues(inv_curve, fac, exponent):
            res = 0
            mal_ecdhe = ECDHE(G=self.curve.G, d=1)

            exp_mod = int(fac == 2)

            full_pp_group  = fac**exponent
            first_subgroup = fac**(exponent-1)

            already_seen = set()

            # Find a prime power generator on the invalid curve
            first_order = full_pp_group // first_subgroup
            attempts = 0
            while True:
                point   = inv_curve.random()
                bad_pub = point * (inv_curve.cardinality() // full_pp_group)

                if bad_pub * first_subgroup:
                    break

                # Heuristics to determine if we can't generate that subgroup
                already_seen.add(bad_pub * first_subgroup)
                attempts += 1

                if len(already_seen) == first_order or attempts == first_order**3:
                    log.warning(f'No generator of subgroup size {first_order} for curve {inv_curve}. Decrementing exponent')
                    first_order     *= fac
                    first_subgroup //= fac
                    exponent        -= 1
                    attempts         = 0
                    already_seen     = set()


            bad_pub = bad_pub.cache_mul(bad_pub.curve.cardinality().bit_length())

            # Query the oracle
            for curr_e in range(exponent-exp_mod*2):
                subgroup = first_subgroup // fac**curr_e

                curr_r = 0
                for i in range(1, fac):
                    pub_mod = subgroup*(res + i*fac**curr_e)

                    if self.oracle.request(bad_pub*subgroup, mal_ecdhe.derive_key(bad_pub*pub_mod)):
                        curr_r = i
                        break

                res += curr_r * fac**curr_e

            return res, fac**(curr_e+1)


        residues = find_residues(final_plan)
        res, mod = crt([(r**2 % p, p) for r,p in residues])

        p = int(self.curve.ring.quotient)

        if mod > p**2:
            return kth_root(res, 2)

        else:
            # We should only be here for P521.
            # P521's prime `p` is M521 (2^521 - 1). Since P521's `a` parameter (-3) is a
            # quadratic residue of the field, and `p` is 3 mod 4, there exists a supersingular
            # curve `E: y^2 = x^3 + ax` (note that `b` is 0) with order `p+1`. Now `p+1` is a
            # power of 2, meaning it's literally the smoothest possible invalid curve we can use.
            # Even more fortunate, negation is idempotent in Z2, so we don't have to care about
            # negative points. The biggest stipulation is that the public key for the
            # first subgroup confinement will always result in 0 or G, and, therefore, give us
            # no information. We simply skip it, and then solve the missing relation.

            # We have a relation d % mod == res
            # Therefore:
            # d - m*mod == res
            # d = res + m*mod
            # y = d * G
            # y = G * (res + m*mod)
            # y = G*res + G*m*mod

            # So by starting BSGS's accumulator at `G*res` and setting the generator to `G*mod`,
            # we'll solve for `m` given `y`.
            res, mod = crt(residues)
            g_prime  = self.curve.G*mod
            y_prime  = res * self.curve.G
            order    = self.curve.order // mod + 1

            try:
                m = bsgs(g_prime, public_key, e=y_prime, end=order)
            except SearchspaceExhaustedException:
                res     = -res % mod
                y_prime = res * self.curve.G
                m       = bsgs(g_prime, public_key, e=y_prime, end=order)
            return res + mod*m
