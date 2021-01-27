from samson.utilities.cli import HASHES, PKI, ENCODING_MAPPING
from subprocess import check_output
from tempfile import NamedTemporaryFile
import unittest

HASH_PARAMS = {
    'keccak': 'r=1044,c=512,digest_bit_size=256',
    'shake128': 'digest_bit_length=256',
    'shake256': 'digest_bit_length=512'
}

PKI_PARAMS = {
    'rsa': 'bits=1024',
    'ecdsa': 'curve=nistp256',
}


class CLITestCase(unittest.TestCase):
    def test_hashes(self):
        for hash_name in HASHES:
            params = ["randomtext"]
            if hash_name in HASH_PARAMS:
                params += [f"--args={HASH_PARAMS[hash_name]}"]

            check_output(["samson", "hash", hash_name, *params])


    def test_pki(self):
        with NamedTemporaryFile() as temp_file:
            # We need a signing key for the DH cert
            check_output(f"samson pki generate rsa --args=bits=1024 > {temp_file.name}", shell=True)

            for pki_name, pki_class in PKI.items():
                if pki_name == "auto":
                    continue

                params = [pki_name]

                if pki_name in PKI_PARAMS:
                    params += [f"--args={PKI_PARAMS[pki_name]}"]

                if pki_name == "dh":
                    params += [f"--encoding-args=signing_key={temp_file.name}"]


                for key, encoding in ENCODING_MAPPING.items():
                    enc_key = [f"--encoding={key}"]

                    if encoding in pki_class.PRIV_ENCODINGS:
                        check_output(["samson", "pki", "generate", *params] + enc_key)

                    if encoding in pki_class.PUB_ENCODINGS:
                        check_output(["samson", "pki", "generate", *params] + enc_key + ["--pub"])
