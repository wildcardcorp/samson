from samson.public_key.dsa import DSA
from samson.public_key.ecdsa import ECDSA
from samson.public_key.rsa import RSA
from samson.encoding.general import PKIEncoding
from fastecdsa.curve import P521
from subprocess import check_call, DEVNULL
from tempfile import NamedTemporaryFile
import os
import unittest

class CertSigningTestCase(unittest.TestCase):
    def _run_test(self, ca, leaf):
        leaf_crt = leaf.export_public_key(encoding=PKIEncoding.X509_CERT, signing_key=ca, subject='CN=leaf').decode()
        ca_crt   = ca.export_public_key(encoding=PKIEncoding.X509_CERT, ca=True)

        with NamedTemporaryFile(delete=False) as f:
            f.write(ca_crt)

        check_call([f'echo -ne \"{leaf_crt}\" | openssl verify -CAfile {f.name}'], shell=True, stdout=DEVNULL)
        os.unlink(f.name)


    def test_dsa(self):
        for _ in range(10):
            ca   = DSA()
            leaf = DSA()

            self._run_test(ca, leaf)


    def test_rsa(self):
        for _ in range(10):
            ca   = RSA(2048)
            leaf = RSA(2048)

            self._run_test(ca, leaf)


    def test_ecdsa(self):
        for _ in range(10):
            ca   = ECDSA(P521.G)
            leaf = ECDSA(P521.G)

            self._run_test(ca, leaf)
