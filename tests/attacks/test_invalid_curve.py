#!/usr/bin/python3
from samson.attacks.invalid_curve_attack import InvalidCurveAttack
from samson.math.algebra.curves.weierstrass_curve import WeierstrassCurve
from samson.math.algebra.rings.integer_ring import ZZ
from samson.protocols.ecdhe import ECDHE
from samson.oracles.oracle import Oracle
from samson.hashes.sha2 import SHA256
from samson.macs.hmac import HMAC
import unittest


class InvalidCurveAttackTestCase(unittest.TestCase):
    def _test_curve(self, curve, inv_curves=None):
        m       = b"crazy flamboyant for the rap enjoyment"
        sha256  = SHA256()
        bob_key = ECDHE(G=curve.G)


        def oracle_func(h, r):
            try:
                K    = bob_key.derive_key(h)
                hmac = HMAC(key=K, hash_obj=sha256)
                mac  = hmac.generate(m)

                eve_hmac = HMAC(key=r, hash_obj=sha256)
                return eve_hmac.generate(m) == mac
            except ValueError:
                return False


        oracle        = Oracle(oracle_func)
        ica           = InvalidCurveAttack(oracle, curve)
        recovered_key = ica.execute(bob_key.pub, inv_curves)

        self.assertEqual(recovered_key, bob_key.d)



    def test_custom_curves(self):
        g       = (182, 85518893674295321206118380980485522083)
        ring    = ZZ/ZZ(233970423115425145524320034830162017933)
        a       = ring(-95051)
        curve   = WeierstrassCurve(a=a, b=ring(11279326), cardinality=8*29246302889428143187362802287225875743, base_tuple=g, ring=ring)

        curve_params = [
            (210, 233970423115425145550826547352470124412),
            (504, 233970423115425145544350131142039591210),
            (727, 233970423115425145545378039958152057148),
            #(929, 233970423115425145520632555873161934836),
            (951, 233970423115425145499640273189159388462),
            (967, 233970423115425145529036018359683613767),
            (968, 233970423115425145534712405853314719057),
            (977, 233970423115425145542179243956857067517),
            (986, 233970423115425145534842704838774057365),
            (989, 233970423115425145516053367946067149978),
            (990, 233970423115425145541201531962363958987),
            (995, 233970423115425145550083740000630277798)
        ]

        inv_curves = [WeierstrassCurve(a=a, b=ring(b), cardinality=card, base_tuple=g, ring=ring) for b,card in curve_params]
        self._test_curve(curve, inv_curves)



    def test_precomputed_nist192(self):
        from samson.math.algebra.curves.named import P192
        self._test_curve(P192)


    def test_precomputed_nist224(self):
        from samson.math.algebra.curves.named import P224
        self._test_curve(P224)


    def test_precomputed_nist256(self):
        from samson.math.algebra.curves.named import P256
        self._test_curve(P256)


    def test_precomputed_nist384(self):
        from samson.math.algebra.curves.named import P384
        self._test_curve(P384)


    def test_precomputed_nist521(self):
        from samson.math.algebra.curves.named import P521
        self._test_curve(P521)



    def test_precomputed_bp160(self):
        from samson.math.algebra.curves.named import brainpoolP160r1
        self._test_curve(brainpoolP160r1)


    def test_precomputed_bp192(self):
        from samson.math.algebra.curves.named import brainpoolP192r1
        self._test_curve(brainpoolP192r1)


    def test_precomputed_bp224(self):
        from samson.math.algebra.curves.named import brainpoolP224r1
        self._test_curve(brainpoolP224r1)


    def test_precomputed_bp256(self):
        from samson.math.algebra.curves.named import brainpoolP256r1
        self._test_curve(brainpoolP256r1)


    def test_precomputed_bp320(self):
        from samson.math.algebra.curves.named import brainpoolP320r1
        self._test_curve(brainpoolP320r1)


    def test_precomputed_bp384(self):
        from samson.math.algebra.curves.named import brainpoolP384r1
        self._test_curve(brainpoolP384r1)


    def test_precomputed_bp512(self):
        from samson.math.algebra.curves.named import brainpoolP512r1
        self._test_curve(brainpoolP512r1)
