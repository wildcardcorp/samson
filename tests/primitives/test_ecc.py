from samson.math.algebra.curves.named import EdwardsCurve25519, Curve25519, Curve448
from samson.math.algebra.curves.twisted_edwards_curve import TwistedEdwardsPoint
from samson.utilities.bytes import Bytes
import unittest

class ECCTestCase(unittest.TestCase):
    def _run_test(self, curve, iterations, expected_result):
        k, u = curve.U, curve.U

        for _ in range(iterations):
            k, u = (curve(u) * curve.clamp_to_curve(int(k))).x, k


        self.assertEqual(int(k), expected_result)



    def test_curve25519_vec1(self):
        self._run_test(Curve25519, 1, Bytes(0x422C8E7A6227D7BCA1350B3E2BB7279F7897B87BB6854B783C60E80311AE3079)[::-1].int())


    def test_curve25519_vec1000(self):
        self._run_test(Curve25519, 1000, Bytes(0x684CF59BA83309552800EF566F2F4D3C1C3887C49360E3875F2EB94D99532C51)[::-1].int())


    def test_curve448_vec1(self):
        self._run_test(Curve448, 1, Bytes(0x3F482C8A9F19B01E6C46EE9711D9DC14FD4BF67AF30765C2AE2B846A4D23A8CD0DB897086239492CAF350B51F833868B9BC2B3BCA9CF4113)[::-1].int())


    def test_curve448_vec1000(self):
        self._run_test(Curve448, 1000, Bytes(0xAA3B4749D55B9DAF1E5B00288826C467274CE3EBBDD5C17B975E09D4AF6C67CF10D087202DB88286E2B79FCEEA3EC353EF54FAA26E219F38)[::-1].int())




    def _run_edwards_test(self, point, scalar, expected_point):
        new_point = point * scalar
        self.assertEqual((new_point.x, new_point.y, new_point.curve), (expected_point.x, expected_point.y, expected_point.curve))


    def test_ed25519_vec0(self):
        point = TwistedEdwardsPoint(x=47994554896164053830959029072481078386599585210356637264868054678660707520716, y=54024386633314616877827082476987868147282925656774767463732970271280810522, curve=EdwardsCurve25519)
        scalar = 1

        self._run_edwards_test(point, scalar, point)


    def test_ed25519_vec1(self):
        point = TwistedEdwardsPoint(x=47994554896164053830959029072481078386599585210356637264868054678660707520716, y=54024386633314616877827082476987868147282925656774767463732970271280810522, curve=EdwardsCurve25519)
        scalar = 0
        expected_point = TwistedEdwardsPoint(x=0, y=1, curve=EdwardsCurve25519)

        self._run_edwards_test(point, scalar, expected_point)


    def test_ed25519_vec2(self):
        point = TwistedEdwardsPoint(x=47994554896164053830959029072481078386599585210356637264868054678660707520716, y=54024386633314616877827082476987868147282925656774767463732970271280810522, curve=EdwardsCurve25519)
        scalar = 2
        expected_point = TwistedEdwardsPoint(x=46226096755287370991107084635004467155978027354820115198405843269492345150021, y=2234645200727986282992513766703393170434492986422164349383711423346156104689, curve=EdwardsCurve25519)

        self._run_edwards_test(point, scalar, expected_point)


    def test_ed25519_vec3(self):
        point = TwistedEdwardsPoint(x=47994554896164053830959029072481078386599585210356637264868054678660707520716, y=54024386633314616877827082476987868147282925656774767463732970271280810522, curve=EdwardsCurve25519)
        scalar = 3
        expected_point = TwistedEdwardsPoint(x=17634806241944143926862694387797098711831272351350528794179127045273395268845, y=37345872894299654648114376969666691683138900003498308543502943378943868815380, curve=EdwardsCurve25519)

        self._run_edwards_test(point, scalar, expected_point)
