from samson.math.general import random_int
from samson.math.all import ZZ, WeierstrassCurve
from samson.public_key.ecdsa import ECDSA
from samson.utilities.bytes import Bytes
import unittest

def build_bad_random(start, stop, c):
    def bad_random(size):
        k = random_int(size)
        return (k & (((1 << size.bit_length()) - 1) - ((1 << start) - 1) + ((1 << stop) - 1))) + (c << stop)

    return bad_random


R     = ZZ/ZZ(233970423115425145524320034830162017933)
curve = WeierstrassCurve(a=R(-95051), b=R(11279326), cardinality=8*29246302889428143187362802287225875743, base_tuple=(182, 85518893674295321206118380980485522083), ring=R)
G     = curve.G
q     = G.order()


class ECDSANonceBiasTestCase(unittest.TestCase):
    def _generate_test_parameters(self, n, top_size, bias_start, bias_stop, constant):
        d = random_int(q)+1

        bad_random = build_bad_random(bias_start, bias_stop, constant)

        ecdsa = ECDSA(G, d=d)
        logq  = q.bit_length()

        ks   = [bad_random(q) for _ in range(n)]
        msgs = [Bytes.random((logq - 1) // 8) for _ in range(n)]
        sigs = [ecdsa.sign(msg, k=k) for k, msg in zip(ks, msgs)]

        lower_mask = ((1 << (logq-top_size)) - 1)
        tops = [(k & (((1 << logq) - 1) - lower_mask)) for k in ks]
        bots = [(k & lower_mask) for k in ks]

        return ecdsa, msgs, sigs, bots, tops


    def test_high_bias(self):
        constant = random_int(2**64)
        ecdsa, msgs, sigs, _bots, _tops = self._generate_test_parameters(6, 64, q.bit_length(), q.bit_length()-64, constant)
        ecdsa2 = ecdsa.biased_nonce_key_recovery(msgs, sigs, 64, True)

        self.assertEqual(ecdsa, ecdsa2)


    def test_low_bias(self):
        constant = random_int(2**64)
        ecdsa, msgs, sigs, _bots, _tops = self._generate_test_parameters(6, 64, 64, 0, constant)
        ecdsa2 = ecdsa.biased_nonce_key_recovery(msgs, sigs, 64, False)

        self.assertEqual(ecdsa, ecdsa2)


    def test_high_partial(self):
        ecdsa, msgs, sigs, _bots, tops = self._generate_test_parameters(6, 64, 0, 0, 0)
        ecdsa2 = ecdsa.biased_nonce_key_recovery(msgs, sigs, 64, True, tops)

        self.assertEqual(ecdsa, ecdsa2)


    def test_low_partial(self):
        ecdsa, msgs, sigs, bots, _tops = self._generate_test_parameters(6, 64, 0, 0, 0)
        ecdsa2 = ecdsa.biased_nonce_key_recovery(msgs, sigs, 61, False, bots)

        self.assertEqual(ecdsa, ecdsa2)


    def test_high_bias_low_partial(self):
        bias_size = 16
        partial_size = 16
        constant = random_int(2**bias_size)

        ecdsa, msgs, sigs, bots, _tops = self._generate_test_parameters(6, q.bit_length()-partial_size, q.bit_length(), q.bit_length()-bias_size, constant)
        ecdsa2 = ecdsa.biased_nonce_key_recovery(msgs, sigs, bias_size, True, bots, False)

        self.assertEqual(ecdsa, ecdsa2)


    def test_low_bias_high_partial(self):
        bias_size = 16
        partial_size = 16
        constant = random_int(2**bias_size)

        ecdsa, msgs, sigs, _bots, tops = self._generate_test_parameters(6, partial_size, bias_size, 0, constant)
        ecdsa2 = ecdsa.biased_nonce_key_recovery(msgs, sigs, bias_size, False, tops, True)

        self.assertEqual(ecdsa, ecdsa2)
