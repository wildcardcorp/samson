from samson.math.general import random_int_between, crt, mod_inv, bsgs
from samson.math.factorization.general import trial_division
from samson.math.algebra.rings.integer_ring import ZZ
from samson.utilities.runtime import RUNTIME
from samson.oracles.oracle import Oracle
from functools import reduce
import math

import logging
log = logging.getLogger(__name__)


class DiffieHellmanSubgroupConfinementAttack(object):
    """
    The Diffie-Hellman Subgroup Confinement attack takes advantage of smooth multiplicative group orders of unsafe primes used in Diffie-Hellman.
    There are two phases to this attack:
        1) Finding residues modulo the small factors of the multiplicative group order
        2) Solving the discrete logarithm of the remaining factors

    Conditions:
    * Diffie-Hellman is being used
    * The user has access to an boolean oracle that accepts arbitrary public keys and returns whether the residue was correct
    * The left over key space is small enough to solve DLP
    """

    def __init__(self, oracle: Oracle, p: int, g: int=None, order: int=None, threads: int=1):
        """
        Parameters:
            oracle (Oracle): Oracle that accepts (public_key: int, residue: int) and returns (is_correct: bool).
            p                (int): Prime modulus.
            g                (int): Generator.
            order            (int): Order of multiplicative group.
        """
        self.oracle = oracle
        self.p = p
        self.g = g
        self._group  = (ZZ/ZZ(p)).mul_group()
        self.order   = order or (self._group(g).order if g else self._group.order)
        self.threads = threads

        if order:
            self._group.order_cache = order


    @RUNTIME.report
    def execute(self, public_key: int, max_factor_size: int=2**16) -> int:
        """
        Executes the attack.

        Parameters:
            public_key      (int): Diffie-Hellman public key to crack.
            max_factor_size (int): Max factor size to prevent attempting to factor forever.
        
        Returns:
            int: Private key.
        """
        # Factor as much as we can
        facs = trial_division(self.p-1, limit=max_factor_size)
        log.debug(f'Found factors: {facs}')


        # Request residues from crafted public keys
        @RUNTIME.threaded(threads=self.threads, starmap=True)
        def find_residues(fac, exponent):
            res = 0

            for curr_e in range(1, exponent+1):
                subgroup = fac**curr_e

                h = 1
                while h == 1:
                    t = random_int_between(2, self.p)
                    h = pow(t, (self.p-1) // subgroup, self.p)

                for i in range(res, subgroup+1, subgroup // fac):
                    if self.oracle.request(h, pow(h, i, self.p)):
                        res = i
                        break

                res %= subgroup

            return res, subgroup

        residues = find_residues(facs.items())


        # Build partials using CRT
        n, r = crt(residues)

        # Oh, I guess we already found it...
        if r >= self.order:
            return n

        g_prime = pow(self.g, r, self.p)
        y_prime = (public_key * mod_inv(pow(self.g, n, self.p), self.p)) % self.p

        log.info(f'Recovered {"%.2f"%math.log(reduce(int.__mul__, facs, 1), 2)}/{"%.2f"%math.log(self.order, 2)} bits')
        log.info(f'Found relation: x = {n} + m*{r}')
        log.debug(f"g' = {g_prime}")
        log.debug(f"y' = {y_prime}")

        # Solve DLP
        R = (ZZ/ZZ(self.p)).mul_group()
        m = bsgs(R(g_prime), R(y_prime), end=(self.order - 1) // r)
        return n + m*r
