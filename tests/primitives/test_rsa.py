from samson.publickey.rsa import RSA
from samson.utilities.bytes import Bytes
import unittest


TEST_PRIV = b"""-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQBUVwJ4kpnFlUTwpIA31fy+KFtcIU0mRp9/UkI3Y9AbMx0PfJ39
XphDWzYuCDh10QHhC/hio0ogzTjNaHQ3cLHuV85/BOQzVymuys3GYrmx4PQ48aaR
U4AB2cjzN03B2r8un7MWvmNrDSOT9RHFvHNzwWZlYjItw5ERY+M4uDvffZpiLIG5
7dGc0Wmcrowt7zJd4xPgcNdzP8fKleCxLvakMJVibh+jsZaBpuaygo62s0h8t7tY
NwCGsQjp6vnyClO49Eyf56t61UXXCzxfRwGQ7OnnFygk4FdH4cQxpmSra9L5FL9k
5NysBXXEk/UqSIc3+FdC+1KqRVXxRKuOYBcTAgMBAAECggEAPID7BdJtvB/ciCIK
1YOOwEAlYk+FkCrj6yvw0tmpBopBk8WbdZNx+ggqMxW0o1igV3kF5IUt/aAb2sfP
b6JKEyksu1Sf/PDPt1RIEMTsYF539Y3uJ51WXH2HOmv3PVWXB3SLvoowujB/0Hnk
GQ2baXRZ5+ttAgWlQWt+K0eHtEkLRVCeJ0AepBOGfCrrjkuayswFF4er5D+8jJZ+
oOsdxUNY6uMntJn2uK/kgWI29mBfkOqG8u4Y5W++F6c3Ye3izDQI1rkN4IFSUDMB
DLlLK5wPbTCayQkktEDiYj4Qb70ylmIWmNzZWM5b4VQ8ceyczT4t9W+fnbZtF9zT
Zc5M2QKBgQCoH3yQUjkWXR7yewd0TPmRbp/Ri7jf8uKzZGbtOtVWnFRolvnnNBma
CJIVQ6JC4H7bBVRMlKH60ybkj0aBWSYsR5MhkKi8CnXE3ErhKSrE3/3YEpPw5s8G
GL90h3ujPaRfUki8bAaA5QL8mwnJni5wDJX9Uxqo8lc6q1Qj4fkJnwKBgQCAbIRU
s76yTpPdz5JONV+gmxEOYGOBijMM308LCCHiuEj/yjp7rxGVct16kmPzYkAMNdtB
9Dpmoa6HTiDFXdJW26sS7EGjY9qQO9cMzGMOZc6Vi4bTdUJfiQBwe0FauDLp9Xl5
r5NUaX3/FeHkNIBVhvcFvfLVN6IT/HKpCZMmDQKBgQCJFyO7i1CBq+1QTIIHk7zt
mgc4F3bpJmU1YumLCC5uMYuivXmJzjISKGr2a/AkGGtYrT/QMmLi5MsSFMKpNsip
0rNm606sBtuBayCj+a2mW//h8UQxbAPkNMnpe5CVy+38zFwDSRMEh7mnwcR5Y0L6
m0izCND0cqgubwZtPBaWgQKBgDBismkHX+3mVSfZMRJuYZ0tT3vPLS59V0aeTDWn
1ryJGlflZat8Bm/8Wx33Udk9R0xSbk2nKunIOO2ZrhcuhjVbhlUW1pQs5wg4w4l6
6EdgbDlD3ISHRX6hK501kyYPCH/FkQMb97JyHJqjL/y/GyseMqvjKT7UOyi0kK7H
gL1xAoGAFizRvHqloxi3Pp+L9S1agxCaSDYcFoE73UCBAfWkHd1Ji/37Qa7bARiW
G8TIq6kR6CylPOz4UiGWbp5Fz0jKZMUROpUZo+g6OLxyJBaZtv9Tj2zF0Ek2w7+f
3eyhIl+K+rhJsKQJeZWrQhJjT+MjSGjMWRowPRpYM8p9gsMmQ+I=
-----END RSA PRIVATE KEY-----
"""


TEST_PUB = b"""-----BEGIN PUBLIC KEY-----
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBUVwJ4kpnFlUTwpIA31fy+
KFtcIU0mRp9/UkI3Y9AbMx0PfJ39XphDWzYuCDh10QHhC/hio0ogzTjNaHQ3cLHu
V85/BOQzVymuys3GYrmx4PQ48aaRU4AB2cjzN03B2r8un7MWvmNrDSOT9RHFvHNz
wWZlYjItw5ERY+M4uDvffZpiLIG57dGc0Wmcrowt7zJd4xPgcNdzP8fKleCxLvak
MJVibh+jsZaBpuaygo62s0h8t7tYNwCGsQjp6vnyClO49Eyf56t61UXXCzxfRwGQ
7OnnFygk4FdH4cQxpmSra9L5FL9k5NysBXXEk/UqSIc3+FdC+1KqRVXxRKuOYBcT
AgMBAAE=
-----END PUBLIC KEY-----"""


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

            der_bytes = rsa.export_private_key(should_pem_encode)
            recovered_rsa = RSA.import_key(der_bytes)

            self.assertEqual((rsa.d, rsa.e, rsa.n, rsa.p, rsa.q), (recovered_rsa.d, recovered_rsa.e, recovered_rsa.n, recovered_rsa.p, recovered_rsa.q))



    def test_import_export_private(self):
        rsa = RSA.import_key(TEST_PRIV)
        der_bytes = rsa.export_private_key()
        new_rsa = RSA.import_key(der_bytes)

        self.assertEqual((rsa.n, rsa.e, rsa.alt_d), (0x545702789299c59544f0a48037d5fcbe285b5c214d26469f7f52423763d01b331d0f7c9dfd5e98435b362e083875d101e10bf862a34a20cd38cd68743770b1ee57ce7f04e4335729aecacdc662b9b1e0f438f1a691538001d9c8f3374dc1dabf2e9fb316be636b0d2393f511c5bc7373c1666562322dc3911163e338b83bdf7d9a622c81b9edd19cd1699cae8c2def325de313e070d7733fc7ca95e0b12ef6a43095626e1fa3b19681a6e6b2828eb6b3487cb7bb58370086b108e9eaf9f20a53b8f44c9fe7ab7ad545d70b3c5f470190ece9e7172824e05747e1c431a664ab6bd2f914bf64e4dcac0575c493f52a488737f85742fb52aa4555f144ab8e601713, 0x10001, 7637900981413881127344732199207423148450857019726723094659043462794313258767201253269496359678839942555541437712415706663660985252940123204794095993626699211163986533562336773310103190916142252882331767886927729021516529141672972169957951166501750445256177733568843099186777096376892875529534391517354389358568809006385725873288954661635538351606457829485241023554979084645466210495420866845750976009860684015622002855709494103022482640146893844516679296838305756556603312962721311081086887412291530082263197989863828789712221961262494351622769754044860656696333724061992404959980518191241190042534000830303328685273))
        self.assertEqual((rsa.d, rsa.e, rsa.p, rsa.q), (new_rsa.d, new_rsa.e, new_rsa.p, new_rsa.q))
        self.assertEqual(TEST_PRIV.replace(b'\n', b''), der_bytes.replace(b'\n', b''))



    def test_import_export_public(self):
        rsa_pub  = RSA.import_key(TEST_PUB)
        rsa_priv = RSA.import_key(TEST_PRIV)

        der_bytes = rsa_pub.export_public_key()
        new_pub  = RSA.import_key(der_bytes)


        self.assertEqual((rsa_pub.n, rsa_pub.e), (rsa_priv.n, rsa_priv.e))
        self.assertEqual((new_pub.n, new_pub.e), (rsa_priv.n, rsa_priv.e))
    

    
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