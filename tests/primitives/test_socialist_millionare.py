from samson.protocols.socialist_millionare import SocialistMillionare
from samson.utilities.bytes import Bytes
import unittest

class SocialistMillionareTestCase(unittest.TestCase):
    def _run_test(self, secretA, secretB, be_malicious=False, validate=True):
        smp_a = SocialistMillionare(key=secretA, exp1=0 if be_malicious else None)
        smp_b = SocialistMillionare(key=secretB, validate=validate)

        ch_a = smp_a.get_initial_challenge()
        ch_b = smp_b.get_initial_challenge()

        next_a = smp_a.receive_initial_challenge(ch_b)
        next_b = smp_b.receive_initial_challenge(ch_a)

        final_a = smp_a.get_final_challenge(next_b)
        final_b = smp_b.get_final_challenge(next_a)

        if not be_malicious:
            self.assertTrue(smp_a.assert_correct(final_b))

        self.assertTrue(smp_b.assert_correct(final_a))


    def test_gauntlet(self):
        for _ in range(100):
            secret = Bytes.random(16)
            self._run_test(secret, secret)


    def test_fails(self):
        for _ in range(100):
            secretA = Bytes.random(16)
            secretB = Bytes.random(16)
            with self.assertRaises(AssertionError):
                self._run_test(secretA, secretB)


    def test_malicious_params(self):
        secretA = Bytes.random(16)
        secretB = Bytes.random(16)
        self._run_test(secretA, secretB, True, False)


    def test_validation(self):
        secretA = Bytes.random(16)
        secretB = Bytes.random(16)
        with self.assertRaises(AssertionError):
            self._run_test(secretA, secretB, True, True)
