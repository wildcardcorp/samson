from samson.math.all import ZZ, EllipticCurve, random_int
from samson.attacks.insecure_twist_attack import InsecureTwistAttack
from samson.oracles.oracle import Oracle
import unittest


class InsecureTwistAttackTestCase(unittest.TestCase):
    def test(self):
        p = 13731998284256471605435391
        R = ZZ/ZZ(p)
        E = EllipticCurve(R(0), R(1))
        g = E(9421522056266036588177213, 9411381440382960840302440)

        d = random_int(g.order())
        d = 12660731876859916047701477
        Q = d*g
        def oracle(v, v2):
            return (v*d).x == v2.x


        attack = InsecureTwistAttack(Oracle(oracle), g, 1)
        found  = attack.execute(Q, 2**8)
        self.assertEqual(d, found)
