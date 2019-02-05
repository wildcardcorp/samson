from samson.utilities.cli import HASHES, PKI
from subprocess import check_output
import unittest

HASH_PARAMS = {
    'keccak': 'r=1044,c=512,digest_bit_size=256',
    'shake128': 'digest_bit_length=256',
    'shake256': 'digest_bit_length=512'
}

PKI_PARAMS = {
    'rsa': 'bits=1024',
    'ecdsa': 'curve=nistp192'
}

ENCODING_PARAMS = [[], ['--encoding=OpenSSH'], ['--encoding=pkcs8'], ['--pub'], ['--pub', '--encoding=ssh2'], ['--encoding=jwk'], ['--encoding=jwk', '--pub']]

class CLITestCase(unittest.TestCase):
    def test_hashes(self):
        for hash_name in HASHES:
            params = ["randomtext"]
            if hash_name in HASH_PARAMS:
                params += [f"--args={HASH_PARAMS[hash_name]}"]

            check_output(["samson", "hash", hash_name, *params])


    def test_pki(self):
        for pki_name in PKI:
            params = [pki_name]
            if pki_name in PKI_PARAMS:
                params += [f"--args={PKI_PARAMS[pki_name]}"]

            for encoding in ENCODING_PARAMS:
                if pki_name == 'eddsa' and len(encoding) == 1 and 'pkcs8' in encoding[0]:
                    continue
                elif pki_name not in ['rsa', 'ecdsa'] and len(encoding) > 0 and 'jwk' in encoding[0]:
                    continue

                check_output(["samson", "pki", "generate", *params] + encoding)
