#!/usr/bin/python3
from samson.attacks.invalid_curve_attack import InvalidCurveAttack
from samson.utilities.ecc import WeierstrassCurve
from samson.utilities.bytes import Bytes
from samson.protocols.ecdhe import ECDHE
from samson.oracles.default_oracle import DefaultOracle
from samson.hashes.sha2 import SHA256
from samson.macs.hmac import HMAC
import unittest


class InvalidCurveAttackTestCase(unittest.TestCase):
    def test_attack(self):
        curve   = WeierstrassCurve(a=-95051, b=11279326, p=233970423115425145524320034830162017933, order=29246302889428143187362802287225875743, base_tuple=(182, 85518893674295321206118380980485522083))
        m       = b"crazy flamboyant for the rap enjoyment"
        sha256  = SHA256()
        bob_key = ECDHE(G=curve.G)

        eve_ecdhe = ECDHE(d=1, G=curve.G)
        def oracle_func(h, r):
            K    = bob_key.derive_key(h)
            hmac = HMAC(key=K, hash_obj=sha256)
            mac  = hmac.generate(m)

            for i in range(r):
                eve_ecdhe.d = i
                eve_hmac = HMAC(key=eve_ecdhe.derive_key(h), hash_obj=sha256)
                if eve_hmac.generate(m) == mac:
                    return i


        inv_a = WeierstrassCurve(a=-95051, b=210, p=233970423115425145524320034830162017933, order=233970423115425145550826547352470124412, base_tuple=(182, 85518893674295321206118380980485522083))
        inv_b = WeierstrassCurve(a=-95051, b=504, p=233970423115425145524320034830162017933, order=233970423115425145544350131142039591210, base_tuple=(182, 85518893674295321206118380980485522083))
        inv_c = WeierstrassCurve(a=-95051, b=727, p=233970423115425145524320034830162017933, order=233970423115425145545378039958152057148, base_tuple=(182, 85518893674295321206118380980485522083))

        oracle        = DefaultOracle(oracle_func)
        ica           = InvalidCurveAttack(oracle, curve)
        recovered_key = ica.execute(bob_key.pub, [inv_a, inv_b, inv_c])

        self.assertEqual(recovered_key, bob_key.d)
