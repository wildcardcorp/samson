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
    # def test_attack(self):
    #     g       = (182, 85518893674295321206118380980485522083)
    #     ring    = ZZ/ZZ(233970423115425145524320034830162017933)
    #     a       = ring(-95051)
    #     curve   = WeierstrassCurve(a=a, b=ring(11279326), cardinality=29246302889428143187362802287225875743, base_tuple=g, ring=ring)
    #     m       = b"crazy flamboyant for the rap enjoyment"
    #     sha256  = SHA256()
    #     bob_key = ECDHE(G=curve.G)

    #     eve_ecdhe = ECDHE(d=1, G=curve.G)


    #     def oracle_func(h, r):
    #         K    = bob_key.derive_key(h)
    #         hmac = HMAC(key=K, hash_obj=sha256)
    #         mac  = hmac.generate(m)

    #         eve_hmac = HMAC(key=r, hash_obj=sha256)

    #         return eve_hmac.generate(m) == mac


    #     curve_params = [
    #         (210, 233970423115425145550826547352470124412),
    #         (504, 233970423115425145544350131142039591210),
    #         (727, 233970423115425145545378039958152057148),
    #         #(929, 233970423115425145520632555873161934836),
    #         (951, 233970423115425145499640273189159388462),
    #         (967, 233970423115425145529036018359683613767),
    #         (968, 233970423115425145534712405853314719057),
    #         (977, 233970423115425145542179243956857067517),
    #         (986, 233970423115425145534842704838774057365),
    #         (989, 233970423115425145516053367946067149978),
    #         (990, 233970423115425145541201531962363958987),
    #         (995, 233970423115425145550083740000630277798)
    #     ]

    #     inv_curves    = [WeierstrassCurve(a=a, b=ring(b), cardinality=card, base_tuple=g, ring=ring) for b,card in curve_params]
    #     oracle        = Oracle(oracle_func)
    #     ica           = InvalidCurveAttack(oracle, curve)
    #     recovered_key = ica.execute(bob_key.pub, inv_curves)

    #     self.assertEqual(recovered_key, bob_key.d)


    def test_precomputed_nist(self):
        from samson.math.algebra.curves.named import P192
        curve   = P192
        m       = b"crazy flamboyant for the rap enjoyment"
        sha256  = SHA256()
        bob_key = ECDHE(G=curve.G)

        eve_ecdhe = ECDHE(d=1, G=curve.G)


        def oracle_func(h, r):
            K    = bob_key.derive_key(h)
            hmac = HMAC(key=K, hash_obj=sha256)
            mac  = hmac.generate(m)

            eve_hmac = HMAC(key=r, hash_obj=sha256)

            return eve_hmac.generate(m) == mac


        print(bob_key.d)
        oracle        = Oracle(oracle_func)
        ica           = InvalidCurveAttack(oracle, curve)
        recovered_key = ica.execute(bob_key.pub)

        self.assertEqual(recovered_key, bob_key.d)
