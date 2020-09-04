from samson.public_key.dsa import DSA
from samson.public_key.ecdsa import ECDSA
from samson.public_key.rsa import RSA
from samson.encoding.general import PKIEncoding
from samson.encoding.x509.x509_certificate import X509Certificate
from samson.math.algebra.curves.named import P224, P256, P384, P521
from subprocess import check_call, DEVNULL
from tempfile import NamedTemporaryFile
import os
import unittest

import sys
sys.setrecursionlimit(50)

class CertSigningTestCase(unittest.TestCase):
    def _run_test(self, ca, leaf):
        leaf_crt = leaf.export_public_key(encoding=PKIEncoding.X509_CERT, subject='CN=leaf').encode(signing_key=ca)
        ca_crt   = ca.export_public_key(encoding=PKIEncoding.X509_CERT, is_ca=True).encode()

        # OpenSSL verification test
        with NamedTemporaryFile(delete=False) as f:
            f.write(ca_crt)

        check_call([f'echo -ne \"{leaf_crt.decode()}\" | openssl verify -CAfile {f.name}'], shell=True, stdout=DEVNULL)
        os.unlink(f.name)

        # Native verification test
        self.assertTrue(X509Certificate.verify(leaf_crt, ca))



    def test_dsa(self):
        for _ in range(10):
            ca   = DSA()
            leaf = DSA()

            self._run_test(ca, leaf)



    def test_rsa(self):
        for bits in [512, 1024, 2048, 4096]:
            for _ in range(5):
                ca   = RSA(bits)
                leaf = RSA(bits)

                self._run_test(ca, leaf)



    def test_ecdsa(self):
        for curve in [P224, P256, P384, P521]:
            for _ in range(5):
                ca   = ECDSA(curve.G)
                leaf = ECDSA(curve.G)

                self._run_test(ca, leaf)



    def test_cross_alg(self):
        for ca in [DSA(), RSA(2048), ECDSA(G=P256.G)]:
            for leaf in [DSA(), RSA(2048), ECDSA(G=P256.G)]:
                self._run_test(ca, leaf)
