from math import exp
from samson.utilities.runtime import RUNTIME
from samson.oracles.oracle import Oracle
from samson.math.factorization.general import factor
from samson.math.general import crt, bsgs
from samson.utilities.exceptions import SearchspaceExhaustedException

import logging
log = logging.getLogger(__name__)

class InsecureTwistAttack(object):
    def __init__(self, oracle: Oracle, g: 'WeierstrassPoint', processes: int=1):
        self.oracle    = oracle
        self.g         = g
        self.processes = processes


    @RUNTIME.report
    def execute(self, public_key: int, max_factor_size: int=2**24) -> int:
        E  = self.g.curve
        E2 = E.quadratic_twist()

        M, _  = E2.to_montgomery_form()
        u     = M.find_gen()
        order = u.order()

        residues    = []
        idempotents = []

        facs = [(p, e) for p,e in factor(order).items() if p < max_factor_size]
        log.info(f'Found factors: {facs}')

        def find_residues(p, exponent):
            res = 0
            for e in range(1, exponent+1):
                subgroup = p**e
                v = u*(u.order() // subgroup)

                def find_sub_res(res):
                    for i in range(res, subgroup, subgroup // p):
                        if self.oracle.request(v, v*i):
                            return i


                # Try on both sides of the field
                found = find_sub_res(res)
                if found is None:
                    found = find_sub_res(-res % (subgroup // p))

                res  = found
                res %= subgroup

            return res, subgroup

        residues = [find_residues(p, e) for p,e in facs]


        idempotents = []
        nonidems    = []
        # Just so we call the oracle less later
        for r, n in residues:
            if not r or n == 2:
                idempotents.append((r, n))
            else:
                nonidems.append((r, n))


        ra, na = nonidems[0]
        rb, nb = nonidems[1]
        v      = u*(u.order() // (na*nb))

        # Synchronize the sign of the first two residues
        for sign_a, sign_b in [(1, 1), (1, -1), (-1, 1), (-1, -1)]:
            r, _ = crt([(sign_a*ra, na), (sign_b*rb, nb)])
            if self.oracle.request(v, v*r):
                ra, na = sign_a*ra % na, na


        # Sync the signs of the rest
        for res_r, res_n in nonidems[1:]:
            r, n = crt([(ra, na), (res_r, res_n)])
            v    = u*(u.order() // n)

            a = self.oracle.request(v, v*r)
            b = self.oracle.request(v, v*(-r % n))

            # As long as the signs sync, we're good
            sign   = (a or b)*2-1
            ra, na = crt([(ra, na), (sign*res_r, res_n)])



        for sign in [1, -1]:
            n_residues = [(sign*ra, na)] + idempotents
            r, n = crt(n_residues)

            gr = self.g*r
            gn = self.g*n

            try:
                k = bsgs(gn, public_key, E.G.order() // n, e=gr)
                return r + k*n
            except SearchspaceExhaustedException:
                pass
