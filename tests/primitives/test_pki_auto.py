from samson.encoding.general import PKIAutoParser
from samson.public_key.rsa import RSA
from samson.public_key.dsa import DSA
from samson.public_key.ecdsa import ECDSA
from samson.public_key.eddsa import EdDSA
import unittest

class PKIAutoTestCase(unittest.TestCase):
    def _run_test(self, key, expected_type, default_passphrase):
        passphrase = None

        if b"ENCRYPTED" in key and type(key) is not tuple:
            passphrase = default_passphrase

        if type(key) is tuple:
            key, passphrase = key


        try:
            parsed = PKIAutoParser.import_key(key, passphrase=passphrase).key
        except Exception as e:
            print((key, passphrase))
            print(expected_type)
            raise e


        if type(parsed) != expected_type:
            print("PKI PARSE FAILURE")
            print((key, passphrase))
            print(expected_type)


        self.assertEqual(type(parsed), expected_type)


    def test_rsa(self):
        from .test_rsa import TEST_JWK, TEST_OPENSSH0, TEST_OPENSSH1, TEST_OPENSSH2, TEST_OPENSSH3, TEST_PEM_AES_128_ENC, TEST_PEM_AES_192_ENC, TEST_PEM_AES_256_ENC, TEST_PEM_DEC, TEST_PEM_DES3_ENC, TEST_PEM_DES_ENC, TEST_PKCS1_PRIV, TEST_PKCS1_PUB, TEST_PKCS8_PRIV, TEST_SSH2_PUB, TEST_SSH_PRIV, TEST_SSH_PUB, TEST_X509, TEST_X509_CERT, PEM_PASSPHRASE
        keys = [TEST_JWK, TEST_OPENSSH0, TEST_OPENSSH1, TEST_OPENSSH2, TEST_OPENSSH3, TEST_PEM_AES_128_ENC, TEST_PEM_AES_192_ENC, TEST_PEM_AES_256_ENC, TEST_PEM_DEC, TEST_PEM_DES3_ENC, TEST_PEM_DES_ENC, TEST_PKCS1_PRIV, TEST_PKCS1_PUB, TEST_PKCS8_PRIV, TEST_SSH2_PUB, TEST_SSH_PRIV, TEST_SSH_PUB, TEST_X509, TEST_X509_CERT]

        for key in keys:
            self._run_test(key, RSA, PEM_PASSPHRASE)


    def test_dsa(self):
        from .test_dsa import TEST_OPENSSH0, TEST_OPENSSH1, TEST_OPENSSH2, TEST_OPENSSH3, TEST_PEM_AES_128_ENC, TEST_PEM_AES_192_ENC, TEST_PEM_AES_256_ENC, TEST_PEM_DEC, TEST_PEM_DES3_ENC, TEST_PEM_DES_ENC, TEST_PRIV, TEST_PKCS8, TEST_SSH2_PUB, TEST_SSH_PRIV, TEST_SSH_PUB, TEST_X509, TEST_X509_CERT, PEM_PASSPHRASE
        keys = [TEST_OPENSSH0, TEST_OPENSSH1, TEST_OPENSSH2, TEST_OPENSSH3, TEST_PEM_AES_128_ENC, TEST_PEM_AES_192_ENC, TEST_PEM_AES_256_ENC, TEST_PEM_DEC, TEST_PEM_DES3_ENC, TEST_PEM_DES_ENC, TEST_PRIV, TEST_PKCS8, TEST_SSH2_PUB, TEST_SSH_PRIV, TEST_SSH_PUB, TEST_X509, TEST_X509_CERT]

        for key in keys:
            self._run_test(key, DSA, PEM_PASSPHRASE)


    def test_ecdsa(self):
        from .test_ecdsa import TEST_JWK, TEST_OPENSSH0, TEST_OPENSSH1, TEST_OPENSSH2, TEST_OPENSSH3, TEST_PEM_AES_128_ENC, TEST_PEM_AES_192_ENC, TEST_PEM_AES_256_ENC, TEST_PEM_DEC, TEST_PEM_DES3_ENC, TEST_PEM_DES_ENC, TEST_PRIV, TEST_PKCS8, TEST_SSH2_PUB, TEST_SSH_PRIV, TEST_SSH_PUB, TEST_X509, TEST_X509_CERT, PEM_PASSPHRASE
        keys = [TEST_JWK, TEST_OPENSSH0, TEST_OPENSSH1, TEST_OPENSSH2, TEST_OPENSSH3, TEST_PEM_AES_128_ENC, TEST_PEM_AES_192_ENC, TEST_PEM_AES_256_ENC, TEST_PEM_DEC, TEST_PEM_DES3_ENC, TEST_PEM_DES_ENC, TEST_PRIV, TEST_PKCS8, TEST_SSH2_PUB, TEST_SSH_PRIV, TEST_SSH_PUB, TEST_X509, TEST_X509_CERT]

        for key in keys:
            self._run_test(key, ECDSA, PEM_PASSPHRASE)


    def test_eddsa(self):
        from .test_eddsa import TEST_OPENSSH0, TEST_OPENSSH1, TEST_OPENSSH2, TEST_OPENSSH3, TEST_PKCS8, TEST_SSH2_PUB, TEST_SSH_PRIV, TEST_SSH_PUB, TEST_X509
        keys = [TEST_OPENSSH0, TEST_OPENSSH1, TEST_OPENSSH2, TEST_OPENSSH3, TEST_PKCS8, TEST_SSH2_PUB, TEST_SSH_PRIV, TEST_SSH_PUB, TEST_X509]

        for key in keys:
            self._run_test(key, EdDSA, None)
