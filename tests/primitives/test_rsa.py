from samson.publickey.rsa import RSA
from samson.utilities.bytes import Bytes
import unittest

# Test vector from
# https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/SelfTest/PublicKey/test_RSA.py
class RSATestCase(unittest.TestCase):
    def test_kat(self):
        plaintext = Bytes(0xEB7A19ACE9E3006350E329504B45E2CA82310B26DCD87D5C68F1EEA8F55267C31B2E8BB4251F84D7E0B2C04626F5AFF93EDCFB25C9C2B3FF8AE10E839A2DDB4CDCFE4FF47728B4A1B7C1362BAAD29AB48D2869D5024121435811591BE392F982FB3E87D095AEB40448DB972F3AC14F7BC275195281CE32D2F1B76D4D353E2D)
        ciphertext = 0x1253E04DC0A5397BB44A7AB87E9BF2A039A33D1E996FC82A94CCD30074C95DF763722017069E5268DA5D1C0B4F872CF653C11DF82314A67968DFEAE28DEF04BB6D84B1C31D654A1970E5783BD6EB96A024C2CA2F4A90FE9F2EF5C9C140E5BB48DA9536AD8700C84FC9130ADEA74E558D51A74DDF85D8B50DE96838D6063E0955
        modulus = 0xBBF82F090682CE9C2338AC2B9DA871F7368D07EED41043A440D6B6F07454F51FB8DFBAAF035C02AB61EA48CEEB6FCD4876ED520D60E1EC4619719D8A5B8B807FAFB8E0A3DFC737723EE6B4B7D93A2584EE6A649D060953748834B2454598394EE0AAB12D7B61A51F527A9A41F6C1687FE2537298CA2A8F5946F8E5FD091DBDCB
        prime = 0xC97FB1F027F453F6341233EAAAD1D9353F6C42D08866B1D05A0F2035028B9D869840B41666B42E92EA0DA3B43204B5CFCE3352524D0416A5A441E700AF461503
        e = 17

        rsa = RSA(512, p=prime, q=modulus // prime, e=e)

        self.assertEqual(rsa.decrypt(ciphertext), plaintext)
        self.assertEqual(rsa.encrypt(plaintext), ciphertext)



    def test_gauntlet(self):
        for _ in range(10):
            bits = max(16, Bytes.random(2).int() >> 4)
            rsa = RSA(bits, e=65537)

            for _ in range(10):
                plaintext = Bytes.random((bits // 8) - 1)
                ciphertext = rsa.encrypt(plaintext)
                
                self.assertEqual(rsa.decrypt(ciphertext).zfill(len(plaintext)), plaintext)



    def test_der_encode(self):
        for _ in range(20):
            bits = max(1, Bytes.random(2).int() >> 4)
            rsa = RSA(bits, e=65537)

            should_pem_encode = Bytes.random(1).int() & 1

            der_bytes = rsa.export_key(should_pem_encode)
            recovered_rsa = RSA.import_key(der_bytes)

            self.assertEqual((rsa.d, rsa.e, rsa.n, rsa.p, rsa.q), (recovered_rsa.d, recovered_rsa.e, recovered_rsa.n, recovered_rsa.p, recovered_rsa.q))
        

    
    def test_factorize_from_shared_p(self):
        for _ in range(5):
            bits = max(1, Bytes.random(2).int() >> 4)
            rsa_a = RSA(bits, e=65537)
            rsa_b = RSA(bits, e=65537, p=rsa_a.p)

            self.assertNotEqual(rsa_a.d, rsa_b.d)

            new_rsa_a, new_rsa_b = RSA.factorize_from_shared_p(rsa_a.n, rsa_b.n, rsa_a.e)

            self.assertEqual((rsa_a.d, rsa_a.e, rsa_a.n, rsa_a.p, rsa_a.q), (new_rsa_a.d, new_rsa_a.e, new_rsa_a.n, new_rsa_a.p, new_rsa_a.q))
            self.assertEqual((rsa_b.d, rsa_b.e, rsa_b.n, rsa_b.p, rsa_b.q), (new_rsa_b.d, new_rsa_b.e, new_rsa_b.n, new_rsa_b.p, new_rsa_b.q))
    

    def test_factorize_from_d(self):
        for _ in range(5):
            bits = max(1, Bytes.random(2).int() >> 4)
            rsa_a = RSA(bits, e=65537)
            new_rsa_a = RSA.factorize_from_d(rsa_a.d, rsa_a.e, rsa_a.n)

            # Here we sort p and q since we don't know which found prime will be assigned to which variable
            self.assertEqual((rsa_a.d, rsa_a.e, rsa_a.n, sorted([rsa_a.p, rsa_a.q])), (new_rsa_a.d, new_rsa_a.e, new_rsa_a.n, sorted([new_rsa_a.p, new_rsa_a.q])))