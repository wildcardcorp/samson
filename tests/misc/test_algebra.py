from samson.math.algebra.all import FF, ZZ, QQ, P256
from samson.math.symbols import Symbol, oo
from samson.math.general import random_int, find_prime
from samson.math.factorization.general import factor
from samson.utilities.exceptions import NotInvertibleException
from functools import reduce
import unittest

x = Symbol('x')
y = Symbol('y')

F       = FF(2, 8)
F23     = F/(F.mul_group()).find_gen().val
FX2     = F[x]/(x**2)
Z_star  = ZZ.mul_group()
Zp_star = (ZZ/ZZ(find_prime(128))).mul_group()
Zn_star = (ZZ/ZZ(random_int(2**32))).mul_group()
Z_2     = ZZ/ZZ(2)
P       = Z_2[x]
P_q     = P/(x**8 + x**4 + x**3 + x + 1)
R       = ZZ[x]/(x**167 - 1)
P256C   = P256[x, y]

ALGEBRAS = [ZZ, QQ, F, F23, P, Z_star, Z_2, P_q, P256, P256C]

class AlgebraTestCase(unittest.TestCase):
    def test_random(self):
        for algebra in ALGEBRAS:
            try:
                i = 11
                max_elem = algebra[i]

                while not max_elem:
                    i -= 1
                    max_elem = algebra[i]

            except NotImplementedError:
                # QQ is not countable
                max_elem = algebra(11)


            try:
                if algebra not in [P256, P256C]:
                    self.assertLess(algebra.random(max_elem), max_elem)
            except NotImplementedError:
                continue
            except Exception as e:
                print(algebra)
                print(max_elem)
                raise e


    def test_order(self):
        # Known answers
        self.assertEqual(ZZ.order(), oo)
        self.assertEqual(QQ.order(), oo)
        self.assertEqual(F.order(), 256)

        # The modulus is random, so the 23rd elem may not have order 16
        # self.assertEqual(F23.order(), 16)
        self.assertEqual(P.order(), oo)
        self.assertEqual(Z_star.order(), oo)
        self.assertEqual(Z_2.order(), 2)
        self.assertEqual(P_q.order(), 256)
        self.assertEqual(R.order(), oo)
        self.assertEqual(FX2.order(), 65536)


        # Verify mathematical property
        for i in range(30):
            self.assertEqual(F[i] * F.order(), F.zero)
            self.assertEqual(FX2[i] * FX2.order(), FX2.zero)
            self.assertEqual(F23[i] * F23.order(), F23.zero)
            self.assertEqual(Z_2[i] * Z_2.order(), Z_2.zero)
            self.assertEqual(P_q[i] * P_q.order(), P_q.zero)
            self.assertEqual(P256[i] * P256.order(), P256.zero)
            self.assertEqual(Zp_star[i] * Zp_star.order(), Zp_star.zero)
            self.assertEqual(Zn_star[i] * Zn_star.order(), Zn_star.zero)



    def test_complex_order(self):
        # Build complex algebras and test their order
        for algebra in [ZZ, F23, P, P_q]:
            i = 107
            max_elem = algebra[i]

            while not max_elem:
                i -= 1
                max_elem = algebra[i]

            for _ in range(20):
                try:
                    AQ = max(algebra[2], algebra.random(max_elem))
                    PX = (algebra/AQ)[y]
                    PQ = max(PX[2], PX.random(PX(y**5)))
                    RX = PX/PQ
                except NotInvertibleException:
                    continue

                smaller_orders = []
                #print(algebra, RX)
                for _ in range(10):
                    rand_elem = RX.zero

                    while rand_elem == RX.zero:
                        rand_elem = RX[random_int(50)]

                    # Assert order is a divisor of the ring order
                    self.assertEqual(rand_elem * RX.order(), RX.zero)

                    # Assert order is the minimum multiple (i.e. 1)
                    factors = factor(RX.order())
                    has_smaller_order = any([rand_elem * reduce(int.__mul__, list(set(factors) - set([fac])), 1) == RX.zero for fac in factors if not (fac == RX.order() or fac == 1)])
                    smaller_orders.append(has_smaller_order)

                self.assertFalse(bool(smaller_orders) and all(smaller_orders))




    def test_characteristic(self):
        self.assertEqual(ZZ.characteristic(), 0)
        self.assertEqual(QQ.characteristic(), 0)
        self.assertEqual(F.characteristic(), 2)
        self.assertEqual(FX2.characteristic(), 2)
        self.assertEqual(F23.characteristic(), 2)
        self.assertEqual(P.characteristic(), 2)
        self.assertEqual(Z_star.characteristic(), 0)
        self.assertEqual(Z_2.characteristic(), 2)
        self.assertEqual(P_q.characteristic(), 2)
        self.assertEqual(R.characteristic(), 0)

        self.assertEqual(F.one * F.characteristic(), F.zero)
        self.assertEqual(F23.one * F23.characteristic(), F23.zero)
        self.assertEqual(P.one * P.characteristic(), P.zero)
        self.assertEqual(Z_2.one * Z_2.characteristic(), Z_2.zero)
        self.assertEqual(P_q.one * P_q.characteristic(), P_q.zero)
        self.assertEqual(Zp_star.one * Zp_star.characteristic(), Zp_star.zero)
        self.assertEqual(Zn_star.one * Zn_star.characteristic(), Zn_star.zero)
