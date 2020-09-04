from samson.protocols.jwt.jws import JWS, JWSSet
from samson.protocols.jwt.jwa import JWASignatureAlg
from samson.public_key.rsa import RSA
from samson.public_key.ecdsa import ECDSA
from samson.public_key.eddsa import EdDSA
from samson.utilities.bytes import Bytes
from samson.math.algebra.curves.named import EdwardsCurve25519, EdwardsCurve448
from samson.hashes.sha2 import SHA256, SHA384, SHA512
from samson.encoding.general import PKIAutoParser
from samson.encoding.jwk.jwk_oct_key import JWKOctKey
from samson.math.algebra.curves.named import P256, P384, P521
import json
import unittest

RS1_KEY = RSA.import_key(b"""-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDY5D2Xq6mcALI5mH+rzw
xIjG6Kmjc6BA44oMNOCuvbVQIGlIGozVnJmyiHuc+DatP5lMGYbeZk7NVSQ/bHew4CDf8r
qjZFdH1gUZK8yNCZW2w9pQ0rgYOd9W7ltPXAcctSkQvoPz2CdhKpnKZyosZLXNyp14rCzB
P95dgmy7n6W5e6Okjg7iE/ECM8WmavYAQET5Fn/kpS1p7z6YPYVfjRpNm+dGsqF6hHbnBj
oZUSUgLBl5T48dHdZP7mNukO8wmkM/4Gq8W7OIhg3en76pp2KRJOIdsYTKRZf5+sq7VoBm
48CRcmUTuI7aOTvbMI+m8NGqQ2x2xqykUbZ6elCbjxAgMBAAECggEBAM9HETXp8GYOpEU2
4IypiuuqidocF7tyNMUZnozvEwjB7PWs510TI0Pw7IMJqK/HYF2dNIcgQJcjX5sHKMjraS
+9gKeSO9uUwF1UmA+jOvfUz1T6b+OsGsTS0fDlSBdqqQ13YRHLnlUX0i4Wb1wPA8LyNFB8
lTglINX82t34xPvk2lpRMBpAwjimQZZsjTo5LTNMFOrArzm0VUW2WmfnBA0983RbLhx412
vk02ROCZk00Z8orTeI47n5xDlbYWOcdrAHcUpeH7dNXzPxqw7sSvunkSwbhnTr5diP535+
66gwdJsh/VBtHOgu3AoL0VYcI5uVXbqjUS5UzbAezI6+s6ECgYEA5wrEH9SXEk+M4kf9ry
37IuYrlyTtMGrQm5hLZiYzEBijxaJyRZNbg//c0jjPARzG0WoGjaAC+aTEp2SNyXtSf51E
DedJ3tlqfqsFFamIG5+I/8CkuwRS4R5ljownSpkyDNB1guOf/JliXQdzodD45N9ZuLSuUw
/VSq+Ps8RnZycCgYEA8FIoMjj4eYdEO9WZnrmDEBZ71rkWStBu2aAsKOLRu/C/ao5UV4WB
whkWFYvmXpCbytCLD0J5/3sdEBynvR/Q9PeLL+krg9j0kDp4Z39Q1IriVV/SZMbUR0A+qC
MjwBckkkpcL3CXfW83z4UpWsA1GVX4JKIbJLpQtwqUHa1ALicCgYAwS0TRrnthnXVCe2/g
pUjgc6Ja9qIJw9oVHBFuqb90tuHM1vbx6ipv/hSncK58egppDbOO+QqGKlXc85zbp8aH3F
S0X0tGpMWo8pCehZBozcEyTI9idDXqzpLF6C/yXPFkUlKt6GyxvVIdRgh6o5bTKIi1njbu
L9oSwX3VQtGmcwKBgQDX4mX7n9QOkCYKvjpvLOWA+UGsRb6x3IYH9+xTmlagx4ec+Fjp+q
PzMkf1eSSshKl/S1Hwll4z1GvqQmOo8MDsnsepdYRCwA4K1ou9JdD97fmeiiLdpwOhMiRX
NKHz+JZA2I3xi+p6owN253+b55iLtv/gIMPTfY/urpEaC73g9wKBgEX6rMznPj9NT/Tgfb
VButVCSJwqQeYG4x6TJDi5xcS005Dw7sGSFntMeFTqp88BewSxx0P6PuDebNQBj8zKCOaA
kmLKOEeAhDcL3QYsFCv/UTMUnTdXoHTdginKg8Vd80jIJsRgVFE7FV3PB6D6faP9izeHNE
fQdk9Ui+yY2YKX
-----END PRIVATE KEY-----""").key

RS2_KEY = RSA.import_key(b"""-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDNenZJKQm0RuL9Vlqc2y
ERACgDvoWcSmz4HU45yglx5oI8+9M5r5k6YOKVo1Mhbv4zPy9TlKijEs0tAwJu9ra2706Y
AFfcj0kHEJAjSgFZPFQh6zE/RUEngL+tSqRX8RIaAEpCh1mKs2md7ZMBNfbx8hvRy1UQpa
rB6/48Cf0R5GaFvpJXwdB5goaDC9BiN5dHZ/dyjJvmeaj6LCrQEl3uu8xqnbkuXBXN2/14
gVI1/rWB1FxRwdKKVDJFdU95V4S5K7RAZvotHXY2LtoYnIy0UnCZrBdctZg8NIbHgjCeKE
HiHDFmaClYvG1T9MHkx7dKMJzmKVIWGYUEX5SnpxLvAgMBAAECggEBAMZ4kSRddTgieEIH
VQLJTgkjw4LKVjf+U37cn6CGG9Vet1G8U+wWRsTyrCmpVjSnBvXtBAORRcot8OyXSZRwzU
+pmpqLSlKKPBmM0AymAON2uDUC/dCFTkefvoTd4hvniHqA6TmVjtHANjYLMcErpNlR57ke
041+1470Kd9ILp9F6QIn2+NMT6RFLhyR0hnIqauIDvVwlny4TlvYCj1gg0W36Wr5XdaKOf
CiuHmFBthQ/7t23wFwALFhOLC8z0xujCzu1v+i8TaDR6NhdDnKekiwv+YLeXAFpJvDuA1m
+o5i6ZSimTrbhb0u+v3x35oxDBMmbtsGm+w0yMWXLIPAstECgYEA4xeEaGUgT3G01lc1ZA
sxK7ACa5Rb0FN53H+GYGbBaZC6eBlNnhnRBeON2/b9R92xPsMeGFb0SHyMN0+rROqe07Uu
DTw9yJotO84v1PbfkGFuWnhRgIseCd98/8FLl9rNOyk7lcl8k0QvaNqf056ZGAfm5vjdEL
H/G/uuUi9rBqsCgYEA56KaW1Z6ouje7kHi5o3u0CCIjNcuEd0TcM6DPt4p4LZAOg9JIWXD
yGl3JEd6Dt5wKX4Z1FxyoqT9mtkaNA+qEtg4rjJYR5/o7pWsib23b9Oq095SQJWQpW6hhz
rjO1CBTtKEKxFUssAIwiF1OpP884mNFd8a8BGf82fTgTTINM0CgYAIecI5WzzfejDzpwGZ
IEnPhZwxg7IBjnwH3MKZKnyhggNTpC4fbns8qweKZCeD3SRWYVXoNqabZfqdvd14jwEqia
KUX+E2cXqqtsFWQ3iInPpPahowoACZAbxal05I9qOeR6Wvq3t4y5yxXyeD8HFqUjEuAa/O
hbYtxzD0ZEysTQKBgDCViG6z+tEEqw2qQB8/keGRkVKJJ56TkipNBnY/PuVlFJ+Y6SvaHn
CAvn6bh1xrB3eMfXpvUZQPqym5c6eLyY5eT7Up1h5fygmQ1zmk0z7fVKtPrEzjkg1A4Rxu
G48rWZPgz9wArJU5dhzRy7bXp2ylYzQ9MXc9GyGAm3o0SfHZAoGAGdZwNSRW91kaDQJG50
XUsyMh9eKXR0iWsG1cs1e9bu+vojEvm8sgy202dsxoHAsAITe2u8qPxlftnaScLzOkDwbv
5/Z3C0oLNrukH0ZQWy8Q1nmanJuPoSnUODkSAJ1rBvqdkF9Re9ifClcqToggOD0fXVXK3h
md+YiysdT80x0=
-----END PRIVATE KEY-----""").key

RS3_KEY = RSA.import_key(b"""-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDWvtueGyJRIYKmYZ/VME
V76h3p9rSOC3XRJdRUilAJxpP+nD3+ZYc/sj0qC3JuYfAqf4sohLe1wkYqCt/grm4oBYaM
D+FeXNA1vTyvEcnSi7D7jDZUgyXbXCKAeWqTCGpL1ddWhEC9DwqE9OMBMXhzLHPVGhPZEh
tW4BwyA6CFtcUIblNhJZWfV14EoPLFCjggE5MHbkECZv5nMdBSmJC/f1IVAac5lgmYGxGb
/MyLlzVkIK7yGZgjjMlr1q8JYtadGFe5DsmFcAXrKntuqdLv/BqjwA2s/p0/KxbvOpsFr2
PCDJ7xucfDcwMTdaNNcG9ymcQZO0q/1PF+mTDNB0KNAgMBAAECggEAXh+XeQwhlXffoPeH
K9UVj4OFCwhUCTJiuIIhN9DL1g0QzvdCgN+VUUjZYDVWOaV5s9blcqQBNYxqXoEXsY4iwC
3z1C4dtNNvey5vi7h7Qmpx7z98jLxS+nu+r5sIKFv24zheQxCCo5sVHEONv/cj+S9RseTV
MD6sdv6RvSYz1IaSlBkwzH7bARW/xrKplNFKHIxSPrwvkkeyFqTsgj6oIP6BdXPIZbX89c
g86s7pWyknVdzTEvtxXSo35i9KqFIuGs4+E11LjVRzslbGpiTxN5YQu2NVjgQX3N2cOyjr
8hFteQSpTxuJEgYnach4Gc0L6/N1B71rho79y/YtLcM9gQKBgQD00KWLeK3hNMADOW7gWN
I7fDRc+EGPeiWsnTy3RDOvV2YGyx/apFk6Z65+NHDLyzGO5W7mMmXQLiXIuH4uQk0emP3Q
R+YS8BhSaeeeFPTBFwTDLmEB8RpnG3lvr+OXkDXYP3glZVZizD09MvxFDeI+tRspcqBMMR
kB/cZjfDEvoQKBgQDgjoTWAoMHDwxhcnQ0xktfDtAv7WBGIydoovCtFax8YdiEVdcEUJfX
JlMwGwCdw6U71/u8wT+VAvqs9XsOgFVI9mcTfX+9l3RoJWZltMrmsMCVNxxbbDz+sFBQhF
YDsNEuhGxwUUjciw9LqCsjiG/vsNqTvf7liFbsNMbZghAbbQKBgDzw+2Seo9odwXaMA3fB
ZIP+RSKngdpvc5VmhsiwJ5WMUg963PEWXEfXq24rK7DvYeTKZDLVdNa/xhQTKQXm5z+oof
YJD9LDBaruRgPp/4tZaYwUrX1IQWRNSItu417FPUIZepUEht6NLOlhGb8u15T4jExjBlgx
GKKQQ6RcM/pBAoGAYH9+QAVWTzs9Q8cOfvtTumbAOkhU3e8PaVzT9l1hARZ/F+dXfggwKA
nVJ9ACxMklgYEAMg4Nh7h/BsJ6/jFR9QfGJc8BjPS/1l10EnLN2rLMH5NOQU9TKtOTv/YO
jIl4avgHLYEQwY2Upht/Zkaka6lhVKoKFpMvX1QSu7ezukUCgYEA4evL4ELaxSYTSVX+Vz
Q2z8l7riPWLFEqPvMHsgW5wKVkXHnpRx+PoeZQK/+AIdEOMh0zeXEecLg7uQ1T4qmWPDxB
uDbtNosYyMryoNAwfQfTcMcc9QvnLXNMqLC7vm/hPlzwvogWyyWeYbOvsjPGSzfaw+DfbU
pVYpArfNuzoBM=
-----END PRIVATE KEY-----""").key

ES1_KEY = ECDSA.import_key(b"""-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgpR4yjoqJ09GAriF++Pxu+I
O1FxF9uAGsniq77Lc6woehRANCAAQbdf1V9k89vTxPbWlzYoiJnk+RZpufb5AX7D4mRJN+
o0NjMxFrNFUyiq3Y7+wa9k06Lg7KL06HN+kaax2/Fp3M
-----END PRIVATE KEY-----""").key

ES1_KEY.hash_obj = SHA256()


ES2_KEY = ECDSA.import_key(b"""-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDxg/XHeJj3sTTsO8Jnczsxzc
jLfwmbJlYMDg2SupAvsrck9iNktrlRlKDX3prWaquhZANiAASzOq9L0SGAfmP1NUxMKunV
mxF707SBdr17rYhes0Q+SpnQ7GWliRcGivg501bxcKxri6EIqPlTSstDmtgCPE7rowKVMt
jHB2itCKnpa4Zw6373AEe8xrxLrYvSlg1uPmw=
-----END PRIVATE KEY-----""").key

ES2_KEY.hash_obj = SHA384()


ES3_KEY = ECDSA.import_key(b"""-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIB94Phb9b/eV0mEt4QHOLB/U
7r3bj1OodWCymrL3peOvkRSRmZqggZqXIUCOiPLLXelwEWeVaIo3zsR59nDiZ4EZqhgYkD
gYYABADYqohYc8LARgtRRE3XVKZ6oRduzHBhiemYBii196XaSSlsSqAApCEvdGzSJPOFMW
PeYxI1nnhsQEtveORMOp6j/QCWMbCkJkoz7q7iivE9i1y56Tm5G9CgqCxJ9mdjOnm0fE0n
bOsQ44F+Gb9beySSMIV3O9seMrQgZicBIKJ2uSx94w==
-----END PRIVATE KEY-----""").key

ES3_KEY.hash_obj = SHA512()


BODY = json.dumps({
    "sub": "1234567890",
    "name": "John Doe",
    "iat": 1516239022
}).encode('utf-8')


# Tests generated from https://jws.io/

HS256_TESTS = [
    (b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', b'your-256-bit-secret'),
    (b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRGVlciIsImlhdCI6MTUxNjIzOTAyMn0.blSEY3tWnWPQW41-zng0dXM0jLjVZ5bqzftwqyw1-KY', b'a bunch of text'),
    (b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImhpeWEifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRGVlciIsImlhdCI6MTUxNjIzOTAyMn0.4JvNuOzOV5a-RCt5Xhsdh03nWD9N82cd__gRwq8TD3w', b'another key')
]

HS384_TESTS = [
    (b'eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.RGFdh_VuEuURSubru7xP4rbaA4boUyueI7rEm75l1cNdE9gQ7H6mx2DYpauBjX5S', b'your-256-bit-secret'),
    (b'eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRGVlciIsImlhdCI6MTUxNjIzOTAyMn0.SOuCwPvnULrtHSDyv89jkfzOcneQAK0F6r_C_26ZeePU1iCmQJ8MNDDzzbYUfIhS', b'a bunch of text'),
    (b'eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6IjEyIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRGVlciIsImlhdCI6MTUxNjIzOTAyMn0.UYel-P8RRm4PXq2nomKr-54tStXrJYoWZFiPcWNJu5AoqjhWWI9FVQSx2BtJ5oG5', b'another key')
]

HS512_TESTS = [
    (b'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.pazba9Pj009HgANP4pTCQAHpXNU7pVbjIGff_plktSzsa9rXTGzFngaawzXGEO6Q0Hx5dtGi-dMDlIadV81o3Q', b'your-256-bit-secret'),
    (b'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRGVlciIsImlhdCI6MTUxNjIzOTAyMn0.7yuFWnHI5iEaxj51-O_xrLTpqZTttVDWcXLOVT9rtdMwFVMGZYhg-xBPGn-N9O5uWbxupBRZ2W1u2FevE0ItSw', b'a bunch of text'),
    (b'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6IjEyIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRGVlciIsImlhdCI6MTUxNjIzOTAyMn0.TCTvIcckDDZVnY4bDhReNvsWpMQ51FZYwtVANwsLW6iN7GxkaOJaZfkQ1kFlRF4MBf5CMYgbRjQk7uv8Es4_mA', b'another key')
]

RS256_TESTS = [
    (b'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.YuPCpCbpIdmRFYtVEFTX0D-hqSlTXmwmNm7LzN7eMwa_nQvVuPUKByPFWe7QLyTV08ikx5a9ThHuQTTzIa6MUHH1xRZQ1YxSsxjqqXtfpP5W2rYhPv1j7Zva64wXz_HT1E-Nx_4BW0__AWwVGYIm_9GU_8EP58MDS-iieR5hNPNgOMMTiyJrAskwecRcqGxU9zO9lRpLvz3A5Youq3nRh12UFbrr6pfg2c_wZ4sgGCUHCcy3IzxtyaXkTsSLqSLKtsPGLY4w-rZDq13-Yii96cFMvoF7A7WxlTRqv4anhrZeqZ779aObpQHs5dHX4bOSXRzbhqB5GUy4VUigyCsoTw', RS1_KEY),
    (b'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRGVlciIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.iRPuZuS5Kqp1-zxMwsu_jqac2NOHyXbkYZzuk1IVkypg2hAS46Jm5e8YR0Iov1NxwwtGxP5mDP4pA3y4K4Y_ZZL9j5nTeKB_xfq8rEB_GUyD4mTbAQHBBnIJUVvpd9NBVyohVSWb4o67ZVtJ2w8CXLeWz_Yzm2em55x7kAa7hcP-_6S42kXQUWK9h4Wk2M6R_0aH8kTk5mqJxiWsB_W2OAICHAZ6m4Z8yqbWSbp1ik1rSk4ytTbYYxci_Vbm5wJR4kuzGrU0Rku1OsorbXH1DWljk4NFPQLUSRAJ1itcD9NOGzNZlrN6LMWYcgRvT_UpWFDjjMfEI3ZhNcSVBE1jxw', RS2_KEY),
    (b'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRGVlciIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.nQu_JzC3ZeuWxslsd5ianowPyv7pVWORiESrFb9EiVEIkSMHqp9__Eved9A3niWeDFE9sItPyjrdURziUeneEsr1T95lDMj3dq2scJMgGIU0IC0KRWlV5CX7EHnkHgQWEo5hkanL3Em73Oed9FKSrxShLGjfQu0PtF20BY3fT40IaDTEgvm6vNk-Zr0AmpFDyKNVd3u_IXDlWlE_mPFNd6wN4pFoYEaY5kNSU7-uRtgd7rmx58VL_ulkNaubMzbma4htCn5o2czqhmZHRb_Hs32LOa3wEwZd9hst8PIC-UWR2OcWmAByOWgwphoCtjIo9wSjSyrJ5Z47f01A9ZyBuA', RS3_KEY)
]

RS384_TESTS = [
    (b'eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.Fj00r13AcUNOS9CmjAP02M7C7tULN6VW38WvmiCWEBV_RkhvssLehet-uRrrLpUDw9GRTD7mU0rP-YxjgJGc3hvrx5lJ9HGTFtuJ11z8N6ZvtIRRwdWTFtn_hWi5U4ZBx1auVzc2Kwbm_WSgGBoIlP_Tn5IjteN9kfho9oLQ-8RWNjcESuxMsVJ9zjptQemtz_SONY79MGbdi1GiDY2199smrsmrMEINViUc5CF5rAb2AzRgImVaBjAcbXUVhr1wF6AoPscUahiFxhiFEkKkgcTn0T0-lFUd3MAJWD0fThyfhWYF9UKRev5ZyE111il41aergmS6xRpwztZeIbfa0w', RS1_KEY),
    (b'eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRGVlciIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.eTpzY_RqalNBM-iWXGjolokIMSlGfsuWtgofCvf3kR-OhiEl6vKRruXqPI757pgafU1O9L2IIrwqw4dsUlMqyC84eQyoQY5tAbiXFqGw3zq1osV4it7me16aSGQzvn0gVUrc5smaKjTw0OQSpKweS-ZlWX9j06fv7dvawofWK3UhKbqcCNi1-VduhuxzvvHM0pdLoub40jCcRfBVV-p9HATcrgi7KbwUDZ5Et3ySBgoesRV95jry4411yrVuwlS-Bs8NX2cBp5zpKX5Ryik0Ey4ds1m0sF5-7kB4UCzNAk_TgkknQyTUFq9hM40EBPmjIpi8AcvkjU6t_eWPkVj5rA', RS2_KEY),
    (b'eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6IjEyIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRGVlciIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.C1KZFXAF4Lvwzhpdn1FSaYb07RW8nBmjd_HvKiPdWH9LzgY0ZVNRkMSuhTKKQrQbtHDXEdVpuH5tjbU95kpmevzB314P-NV_OCbKu_hdG-D1o-LIYYKYJVbathWGUEps9ejeN5qiRUrCDSr2_RT-7yFDQzBNrUBe5iAmJWYtr8k2Y8fo82WF4mHgVpCb4K1H8foeEQWDZYEh7pZ2BUxA6Bn6UaLyBj-oARTCwt8eCrDftW_i5zLNhFOMo4UMHNCxiW9xHcgbXRYJYbJe9ff9ggNQwnTTUp-utU9BJyxuS66FHPzWfQvrBkq15XxaKE8pJHusDUYeHu0d5ug9Zyn8Mg', RS3_KEY)
]

RS512_TESTS = [
    (b'eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.QgGJ2SIGRhDolXNkwya5hAo_Jf_A1qa_Yv-6Rin3kQaP6t5HcinH88t2u0IXRHHOiokXfMsrJbxPSjLhQTylQ9K0MI1cwANcGwpVnQ1fcRFI5W2JJTr7fgIUc-aZOcKOwQrMA3OJ2hQpFfmi-tNCFrcVWKdQgTPazDtYgspKcmvnP40R319b8ByjXahX0hiXgHofi-kYoXkFgnC1piQsvIxMZO0tQJz-BbvqryowTNc_W_Me_rGDLtrKCD9RLsuCh9wAzNVsAQvyllZgkbZ4sGgY_B7Om_1s1a_DE7OgJIGKc4naUmUCqghf-gNmdVzxE-3gT4Wmypl3G_mwz-xgJw', RS1_KEY),
    (b'eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRGVlciIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.Xp-7SOE4mqjH54vr1H7KYN-9K7HSQ2kVtriyROnPUdXFmx0vxcWTUpU-4pv609hiq1apAazbL5sDbEwP5AwEJMv8-4m69bEiKvWxdC-fDoh1fOpVI5b_AUPqRN0kwZhXL4SiB-7oYQ9_-hsCLXWu4X1XU4wBFC2Ku3mQRSznpK75A4iVeuUL1ede5E8UXa5XsN99kzUZI2duwchj3gPgK1TkOmWvuz9a18WXrkzdBUC1LR3v-r6fqxyjSDNYSolu8RGUEYUluWnqflwMGmkf8CJlxLh6tFiuxuA2Wo5RzE1i2z_I6heG0GzaOOvXToY2jvxjzQysu3p-j_8jWqi8lQ', RS2_KEY),
    (b'eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6IjEyIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRGVlciIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.ac26gNoN0UIqPy76IVHIVKCIaaMNPYnVL6snz9HwAP_yr36jXlg_5cbjo4XrmnAozn861gDuCy32U1qgauO_BK3Yu5Bcd1rzGAA1W97-vHBW7ley1RkdZbpMyUsJ8OvUa4gJ-DqV-nKFDWQ4PCzVDqeSb3HW2_UhWNt1fE1Ilw7nL_Hz4DtBggsNuH6b3HTd6GSw8-x_lvXpxrMUI6pF9a1i-FK0tCO1A-bm2A3mehH39mBvUOMvKcji-fETRyvM_SESU5lYWbv_WkrNWTEfGvHhuRq5h9vm7UXCDhRpgjV0M4wsuFF-8RQ4XvkAFIdpc2FFnUwV4MCAAvIw5Lt3gQ', RS3_KEY)
]

ES256_TESTS = [
    (b'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.Rq2SQguv11cCny7xaYa0G0f__CbcKnFVE8BJko6c3XTOwohw1pHa48s0ikdsUxX13RQOVzvWLkQdHuhJrTvJZw', ES1_KEY),
    (b'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRGVlciIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.m2RfuZS2NOjKFefzMcAPDL7EIwj7ewCMO2WgSMNuxc0-zp8z32u2MwtHyM6iZH5BH6zEyR8KjixsOUtOCHxNjA', ES1_KEY),
    (b'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRGVlciIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.6vQbW96e3H1ZrggmsGqHVjEx4O4jr-NIBt1sTtHMKIFv4rXMLDj36VtQCXQAqzTUUAhp14EqKU3yHd_u9m7ENw', ES1_KEY)
]

ES384_TESTS = [
    (b'eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.eJSBpuRfvEcYpDCTqi8gobTrK2czA1CmIYcrcN4caHl01Qk0FyO5e8TpHx6OiDmZ94jepBGRW8GyfaJgwTX28byAhwIKT3NMy0_KGHICJ9v5SjrsdMtWbDkjCBLP0ffo', ES2_KEY),
    (b'eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRGVlciIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.X1mqzDhq5vPfoXtLyU6MJfJ89Fpbs7Gb9rhyeIg_lXF81BFpQI0acGbFvyghI4gqJ2unUThpYd4zRwFAXiXOBNE19AzLO84kcDKy5DvA5ixWAqgqoQ0EUsK-FVtkXdlc', ES2_KEY),
    (b'eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6IjEyIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRGVlciIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.hxS6Ct5tqLGAk5MoDCjAzuru-GraXp2UE6bSSACWVZB-RNfQMogFuBT9MDrXciHZQe8FSBEn3JxWGIxKLeeGSfaVULq--BvwIdF2FMcsELVjPsCo74Ic0011xgXSODwe', ES2_KEY)
]

ES512_TESTS = [
    (b'eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InhaRGZacHJ5NFA5dlpQWnlHMmZOQlJqLTdMejVvbVZkbTd0SG9DZ1NOZlkifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.AGFI0jBboMp9qKZ-j2rjc35dFxTGmfXX_iLmGMxuN25t8CqG559NaCkUSu16u55aFc3NrAskE0vxJHflQfVsgrZ_AMMiTXbXYHUNnrIBV3QmWJOrv_RyUWhCPK3IQ4D81PSRQSpN-sGnHWwICinnsUj2l8vkVFOeRil4Lt8_oe6uATpb', ES3_KEY),
    (b'eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InhaRGZacHJ5NFA5dlpQWnlHMmZOQlJqLTdMejVvbVZkbTd0SG9DZ1NOZlkifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRGVlciIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.AaNZ7Fu7jBBs1BzBraM2JaQ7_0ntUjhIX4u3jt6AWdXmRjHwwKUpwxUVg7E_sr7jYjJYg_ZzyNAbDYBtIUlFTZTkAQMQRFE9cgmMZdXC79H8OfsP5aI4Vu_jRmDy-N8z-ojbWt8n3KH9MFF1p-km7QsG79v1swp2QyewJRGAcxs1H-P_', ES3_KEY),
    (b'eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InhaRGZacHJ5NFA5dlpQWnlHMmZOQlJqLTdMejVvbVZkbTd0SG9DZ1NOZlkiLCJoZHIiOiJoaXlhIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRGVlciIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.AbrYssu4xKthQ7cYfd_RI-UaunmoRDjRNeEBQ5VgBYB5TIdvt7uy6Q7_wKwQ-rbBxycC4OKTH2VfUKOBchSYbjIjAB4JXgCQZOlP-KJR8oaMRnBS4S38_4EyJ-3kgYlRgje8a9dAra3r3y4QPr7XT5rQNq4Vn9E-RbmLa0Ai9JObbOKd', ES3_KEY)
]

PS256_TESTS = [
    (b'eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.OBhCNHh2JMlGtmTx1AwXLPhu_9kupskyXgnyk4g5xNaEnaESt6iSv6n5XyDzXa1iW2yp4iTMP0MhfiumCUqDLFM0j6aMz0N0dKs--mJPtCqq74iM_nqPG0ErM8_mj-8d1aabwIis7vf2NOL5eQcE_j18aqPTzz3TCkWQOCdd2peeCVp0HvyoWcTUY-Ti4Uw6pnS0wohWphDkq3a7iBTxyjQuAwHQjFV4Th0Jzq40-6C4W1kfZCoLmqLSZWhzD4Y1G3NLSVh_c7OkkHgegXqDYKE44IpCYAaSlRWkr9Lxu7x4LJiT_i87Z5vpP4JwLZoGrB5Z99rX_kRJHNuJCTI8mA', RS1_KEY),
    (b'eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRGVlciIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.jJ-lDbBNcZv57CLfijmsvFyhcESt0miV-Nx-78iCefefgUkysulR6IwqWy0fVCIUWTHAq3hU-wnTvBhk-84IxzokYWRI5CQgaeN0YJiwXHHYjk9uw4YxyRE-nQsePdVXqYPN1i3rHSEXVJdgmdI6lGyyaeJ1OfW2Zjrd4dmIF_c8P14zB9tdnd6LMqBUcSugoZ6bOssFU5N3dczfWVl7fOSvcoaY8JJjLAplvCkPyRE-eN6T_wlxpZq5h4kPup202lYOfew98f0jDKReBXzqh1hn2VCGfAkvaONhcpN4Q-c_Lx9AUssPXUXJ-5Nw5G1t1JKFWe7uuFqwgDtPWSoHpw', RS2_KEY),
    (b'eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRGVlciIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.FF4l5RVc--12gqFlBZzeVks_B74wMWF_mnh-UO85sOfAZwZ2Uq-55KlA57QYNLjD-I7pYx7jUvC_Ll0WObayG1fWXWT1mz90MuFLgkk6MXHUBYICDeOiuMCTPVpHmmk8KVb9F4x6U31beYXbQHXfsCKAageZ6nLUGMDosBSwFeM3sIgHEtEkAioclYiaIZjKcE9JQWaFTbl_uaprR-C1A_VoZxwAoEGJsHxdNtSqa0aA6TN3L1FQK6Agj6hPYvDnG9VCkH4c3w-BOGbfNsil3qJmaMiJJ0zxLhNqx6VC5Hbh6E690l40rtuB81Fq0d07AKm94FpsncV5lS1mMdjZew', RS3_KEY)
]

PS384_TESTS = [
    (b'eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.foXJcGrODV8-s_EjYDMGPMwdW96YELPMqK2UpizMmxADu7qk1OJ2lYVbe9l571joDQfSDBhYzIbS4zaM_QjcwyNQe5yQmaZWpXY2X0CIH3dMotYmClhj-YCfO2gaZFZvFiVCDurXKVuJWhbist5sT_XKnwOuYIvnSv3d12Ybh5jkqH0opzwb2kdQ86lcQJD_6tW9i2n0XG8bGn0cDEGK_Ra6rsGvBYijue5Vdgqy7USLhWvAV9JPKXQQDRA9rWkqYVrRkO4Cb7YgLEm2KouLoQ4sWKjXOwg6B3Ec-yF9I6XRxdvLcLEtYALRsIfU1NFrQ1FdnmStmvtpZOUwCFXGsA', RS1_KEY),
    (b'eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRGVlciIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.VbUVUhZ8a_3fSHMxEReCBQ69Lyy7pVeuYUOYEbtVw08B7bBHKNW7xZEHbmtFRlW4KO11S8-I2NEY36W8MIPjITG5_Em1pjsca0sp8ZRirwAfrflM2qIzBGzV3F2i8Nysiium6EkRBDQMZW1QmFHiBVtOJpyPeQAf8DTbMjXMETer1-buXGRqQusgYCC1Q6XehNDLeh7NB1Ob-m4oGoucGYQ7GmdLnYQWmQeoMs4XJI4p2N7e8zM7t78XH2V6Y26s-9CjIYraxRqfaJgtyJEf0Jeb9NsEQ4AwKMWn-EyS6297x8Zuux_4bn1vnHccrNejhnAOf6oFybJBsE024oMYxw', RS2_KEY),
    (b'eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6IjEyIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRGVlciIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.nXt2Tt_4u7lAA_BqTGj6S8fgbcV5tJ0D5q3evmXEUDzw78m2Fx-VnwBIn6-mW_YlqY1YCmpjQzvFXDFwwGfxs6ropyc2ga8r9AArkYbtAmaQ74yDzeqbekwYcJt-YFzXfyb9A3Nm8BtXntFC-r4CPWlvm_jeLtb0fs788A3EfTKO2pb3rkZr6X9kyYGidfB-5XWj1ZypeJDB-Bk8l5HODk_-ZD388M5DzxAUA3nG5q9gtom3l3Yd1Egdh1OHnqDYvekFYkLE_tREG9fGUPGHrQYcpW7TCE2V0sy92sfgNOMJb-5PbgobjcgpjDEw_ExOzwAYkeKLqjfcaFs4YKFqKQ', RS3_KEY)
]


# Tests generated from jwcrypto

# from jwcrypto import jwk, jwe, jws
# from jwcrypto.common import json_encode
# import os

# key = jwk.JWK.generate(kty='RSA', size=2048)

# payload = os.urandom(70)
# jwstoken = jws.JWS(payload)
# jwstoken.add_signature(key, None, json_encode({"alg": "PS512"}))
# encoded = jwstoken.serialize(True)

# print(key.export())
# print(encoded)
# print(payload)

RSA_JWK = RSA.import_key(b'{"d":"0WxnT9XCBIHEVDdFg7deP60CbNbepTGawsRItyEei6SrYCpPxwXgk3yryPhq_nDTtOGjR2W8oKaMRcJbb94EYYdWzhyiToJUZF-cdiwfFEZR_1beudFPS0w3l5-Wnzp5NDqSQ87B9lCpOSycMr2cRDQjI6RftLMxEnGLuDrm9MOxdrW741cpLCNuq0O3nkcgx32-bOmOAO4I1rMuJHccWxR8ytTedoIKZLv-ik4QGnB9eTMkGpqS78--bu3QZRssUyngEZ1kb4YKXqZ-qstx-87kLCu5RldIkZLEOTZR2OUIhG6wLmJqpMbgubKEsu7kPrx-XeETUO2buniPMxTrsQ","dp":"2JDZLdRuKAZKqGk4SMA5ocEyoyNfR_eYi7LMGtg-p5Azwpc_r1trlu95vo5OqgOYqsHSkwq3UbAb2c0jX_7ELCFCe1JsNaHVDUqFp-N17Au3hzcncV_6WN4_0QfhZo7_IQn2ZkdlwR4KDlrXMqGKoET0YkBkRdHvvYTcLWloWmk","dq":"mP49edxp3N_p1d-_8wK7oqu_eTYnNaj0jzG89UymFMqU8C95ri9_VC5CxLEjbZPr_joM_wQkALaH9pli08nTNz_VMwbXqMjg_2VVQ4uJwtOBflB-_iWNZb_PVt1W5KtmxN7KaeqonHDoCSU57pWGfoQPM1pKrIZ33VxHtTeyh_U","e":"AQAB","kty":"RSA","n":"8mASEPU3mkfgKhPx0XLcL7NDopsbUc4inz7sPvTBWXoUgEpJJMsXVDud_wiRGEV8TGPEGEpXIHghlPx3Ml0oLvX_OE3eTEl8P6ctylKQkXxtcoL1i-WMmsEUL0izRZ71TWr6ayOJfLyNSu6D4yEVVTbwPnUTuFlkvFAL1Z_t18scGXXxIB5VXdtEWkRmdYqBaZ-Zvv5RdGtuAeAD6UD9ftWngiPROpFWKLpSkO07r6Hx3LiO4-Dp9Q2CUpzvExGrOnlZFoo8YLQSYupHY-ftvoDlYplYtWis9436D9k4aLiEsp-UXq1opyCSUXsoDQw57vW59KnGNJ0Vl-xGXxBzyw","p":"-_MVaWowZmWGbma3P5xAhXkUEKjq3rwBH7G57HOZKxbjGL1igweB0le4HeJd7y_XkMOm3GHcYf4yxQpz83w_1bUJy7v-0ZaSqYNzhB_kS4kUfrXQyTlA8qyJODerwf94r5nNh-ruqlnENN1WeRyc3OkmLts5eVv7N4Do5urj4gk","q":"9kWVVcOvoBXFz8ufL5CfZBwh4m6-JArhE-V3cummPrSrv7D8s_0EPGXOCx2964xQpdVwhRtFKH8eICBabOh9ddBqwlE6ycpQTx1eNXN20NzAuASCoEQUvsdA5NqMblOy_TsJn-4B-zSoH18Nd5o4cHD21CiU1iSsNUvGNlkCDDM","qi":"EsaowWzI_yZ7ufGejoVgKMSzvG1ZQewF3iAY31yly1s9YHDgdybsCUurLdH4R1UNv4JXsQ_a8AT8FTkdH8mxslqNbE6-qQ99yL9_1_rtrdnsMZKmFjfVTmnaR_h_hZ_v2yU54js0FgC1AGRwlnegpTYFjsYp6HjUKyPk6Tu8pWg"}').key

PS512_TESTS = [
    (b'eyJhbGciOiJQUzUxMiJ9.aoUpbpm4jMzrF35JPNtoEwQ-fIOkfEYc-9gJsfGjTc_drqJ9llNqj78tox-T3ym5HI-Cnf7TTjc783S_87ev15FiIjFHBA.Y_pICxKy4iO86pN4ArAxuMhqLUgA-QXMaoG3rt44_Fbu-vrAOGIuNlHH01HV92glblPVKrDBHb5y_03SuPUWAFn-BTRgRImrSJbkSJCrKGzFiRi9z3sxNusdD-MAyxMcp2X93YJBriyQUTvY8pp-hBxdtAugEKkec0auG58ad55ZGRRTP9WDdD82N8i5UszRLr6acFMwjXkQ7NkBEwvrplhTjomtnt_6nw5eCDWDG6URxjs2NnaIjTzIikC_exr6lDWFyGUTtzLbpVwdfIff1EluuoeeZPyh7e_ykI69CERHOmauaGCett8GrSpM8G2OxlaT-CJEzr9ASgcb_PKzqA', RSA_JWK),
    (b'eyJhbGciOiJQUzUxMiJ9.H_59YCb0FrYZl8XV9Mmo1GwJLBg4ozBRyMuxbSNaTVwxypgk4uDo7Hi78BiVWAcj3YCo39dxhhjLpOMPMsCxqPRoJhwBxg.yYxsx3ERbu6IJMy49wx6DculcSSJBDp3IbaTaLo_vAyfOeJ2_1HCroNvh-I15i0VY6qYvBQQa771Tll_eSvDPoovaxE25ShJr4ZmuYAqju0gwkkvepSlD8x7gy6Q8qKXGIqJ64sg5gWMnMADPMlMEE5Ti3EpYG1Xw9X1JdHfj0TmL9h0_7OQaXTfHQjIApy0tNVjiIKemkUsJKAPpxCy1tSu-Ya3_woM4hpfxqf5jTvbwvf8l-SiGZu6nG9e93u_5wINmYDsJEhGtTXbaoG60QqyyUN1oVYb4HEmCgqXvN3n6drwe6iizaeZ2syukLilJQg79ewjRf1n3xHHl89x2Q', RSA_JWK),
    (b'eyJhbGciOiJQUzUxMiJ9.d3WkFBIJmbL6e941_wPY0A7GbRBVBvlqqC1AQCKimav6e1cjKZWYygdTnu0d8mfGFS-DGgq_1nqChVEaY35f_ggfLD7yOQ.ePtWFZzHekyvODqoZ4DOPfWaBlsGvB_x64Ft5Bl5NuYSxR3COmePWTIPBhV7biW9iUTkpsPgl8NjtCX39Tvu0rq3lOQ62BPOCm5m59gmm4BWL6s_7MR3sQ33hDG4wfrFvo8U821w07iW09s1U1Lr__d78ffSC91igpgZmxKI9WUF5DrTJBFEyXkFopszmF17NTzBkzxFAnbq9Yi-PVetrHQHcoAdA67mqvpSoYcrH3GqY1OoZMyuQ7XjRN5bOtIYWeOt8ROS8jFgJQ9gpZc9KjeI12KnNkuHVBntE75W5C6Vb_iLn9dcJT7ExdR_3f9qsP2YHNyWHGvMzP1S7kk_nA', RSA_JWK)
]


class JWSTestCase(unittest.TestCase):
    def _run_tests(self, test_suite):
        for token, key in test_suite:
            jws = JWS.parse(token)
            self.assertTrue(jws.verify(key))


    def test_hs256(self):
        self._run_tests(HS256_TESTS)


    def test_hs384(self):
        self._run_tests(HS384_TESTS)


    def test_hs512(self):
        self._run_tests(HS512_TESTS)


    def test_rs256(self):
        self._run_tests(RS256_TESTS)


    def test_rs384(self):
        self._run_tests(RS384_TESTS)


    def test_rs512(self):
        self._run_tests(RS512_TESTS)


    def test_es256(self):
        self._run_tests(ES256_TESTS)


    def test_es384(self):
        self._run_tests(ES384_TESTS)


    def test_es512(self):
        self._run_tests(ES512_TESTS)


    def test_ps256(self):
        self._run_tests(PS256_TESTS)


    def test_ps384(self):
        self._run_tests(PS384_TESTS)


    def test_ps512(self):
        self._run_tests(PS512_TESTS)


    # https://tools.ietf.org/html/rfc8037#appendix-A
    def test_eddsa(self):
        key   = json.dumps({"kty":"OKP","crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}).encode('utf-8')
        token = b'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg'
        jws   = JWS.parse(token)
        self.assertTrue(jws.verify(EdDSA.import_key(key).key))


    def test_gauntlet(self):
        for jwa in [JWASignatureAlg.HS256, JWASignatureAlg.HS384, JWASignatureAlg.HS512]:
            for _ in range(50):
                key = Bytes.random(16)
                jws = JWS.create(jwa, BODY, key)

                self.assertTrue(jws.verify(key))


        for jwa, curve, hash_obj in [(JWASignatureAlg.ES256, P256, SHA256()), (JWASignatureAlg.ES384, P384, SHA384()), (JWASignatureAlg.ES512, P521, SHA512())]:
            for _ in range(10):
                key = ECDSA(G=curve.G, hash_obj=hash_obj)
                jws = JWS.create(jwa, BODY, key)

                self.assertTrue(jws.verify(key))


        for jwa in [JWASignatureAlg.RS256, JWASignatureAlg.RS384, JWASignatureAlg.RS512, JWASignatureAlg.PS256, JWASignatureAlg.PS384, JWASignatureAlg.PS512]:
            for _ in range(10):
                key = RSA(2048)
                jws = JWS.create(jwa, BODY, key)

                correct = jws.verify(key)

                if not correct:
                    print(key)
                    print(jws)

                self.assertTrue(correct)


        for i in range(10):
            if i % 2:
                curve = EdwardsCurve25519
            else:
                curve = EdwardsCurve448

            key = EdDSA(curve=curve)
            jws = JWS.create(JWASignatureAlg.EdDSA, BODY, key)

            correct = jws.verify(key)

            if not correct:
                print(key)
                print(jws)

            self.assertTrue(correct)


    def test_json_equivalence(self):
        full_parse = JWSSet.parse(b"""     {
      "payload":
       "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGF
        tcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
      "signatures":[
       {"protected":"eyJhbGciOiJSUzI1NiJ9",
        "header":
         {"kid":"2010-12-29"},
        "signature":
         "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZ
          mh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjb
          KBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHl
          b1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZES
          c6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AX
          LIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"},
       {"protected":"eyJhbGciOiJFUzI1NiJ9",
        "header":
         {"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},
        "signature":
         "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8IS
          lSApmWQxfKTUJqPP3-Kg6NU1Q"}]
     }""".replace(b"\n", b"").replace(b' ', b''))

        flattened_parse = JWSSet.parse(b"""
     {
      "payload":
       "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGF
        tcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
      "protected":"eyJhbGciOiJFUzI1NiJ9",
      "header":
       {"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},
      "signature":
       "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8IS
        lSApmWQxfKTUJqPP3-Kg6NU1Q"
     }""".replace(b"\n", b"").replace(b' ', b''))

        relevant_full = (full_parse.payload, full_parse.signatures[1][0].header, full_parse.signatures[1][1], full_parse.signatures[1][0].signature)
        relevant_flattened = (flattened_parse.payload, flattened_parse.signatures[0][0].header, flattened_parse.signatures[0][1], flattened_parse.signatures[0][0].signature)

        self.assertEqual(relevant_full, relevant_flattened)


    # Generated using jwcrypto

    # from jwcrypto import jwk, jws
    # from jwcrypto.common import json_encode
    # import os

    # key_a = jwk.JWK.generate(kty='EC', crv='P-256')
    # key_b = jwk.JWK.generate(kty='oct', size=256)
    # key_c = jwk.JWK.generate(kty='RSA', size=2048)
    # payload = os.urandom(70)
    # jwstoken = jws.JWS(payload)
    # jwstoken.add_signature(key_a, None, json_encode({"alg": "ES256"}))
    # jwstoken.add_signature(key_b, None, json_encode({"alg": "HS512"}))
    # jwstoken.add_signature(key_c, None, json_encode({"alg": "PS512"}))
    # encoded = jwstoken.serialize()

    # print(key_a.export())
    # print(key_b.export())
    # print(key_c.export())
    # print(encoded)
    # print(payload)

    def test_multiple_recipient_verify(self):
        key_a = b'{"crv":"P-256","d":"GRv1Mpp30nHVfHtnB3XwvFyQnUasU7TtSeIxhnit_mQ","kty":"EC","x":"odJQgm0v4FmQ2klGf0cbUrdTdsDLrHWqjw3MjRw3CU0","y":"RDJxZ7COPk8pnnwOuKN-i5bYGMhQrUzgdydgkG3BarA"}'
        key_b = b'{"k":"EOMbE3QXor7d1Fb3slJVYXVzZyfhiufBefBQ_phUlhw","kty":"oct"}'
        key_c = b'{"d":"BaJsxmMk3athcX3h5VQqAAVQWWAupHHlysm4o7aTpf-0-oTL4ClWsDEn5PbsKpBxliTCfoOCHKdizAIyr-b5ZeFUPrFTwNxdutlCb8HKpiyIvJz09JQ38nvZtOwMykOZCF6rIPkZI-L0UGCMamvMQsyg1cYAbC3T2MpJaZZUfHqTT4AwpgIo7yXuDGrSFz-B4F0yJNR2-IbTtgDS-N4HdX8hvJijjX8WfnFxMRsEXYnzjgeYyu6gTy-wrhcy_0BiJOGSdJL-EcOndhHCW0JGz0oYCArTmP9Oppd31ftBKj7SxvmHxkh4KqTT7bFLeI9YNPh0Tx-RYxc4RvJoODHwIQ","dp":"NSU8GMWE43i5MO6IAA2mBm4X342SsWYF114LP_GewbgcdSwNLqqWkqNDBMqYbUb7H4H5mAQ-YdGKYVu9ceOyS4b-bQh1PLxkkCANdM9juTRfLNdeVaeAjGvJzNvTp7gg6DphFbeQ4tV4QfACYGKbNbpKxP10Wk20-eO1djMSfg0","dq":"LzmIr15O8ON4G_j6Kds6cfsipA7QQsZ5DOH5GERXoT5vSkSJbXjwconeXNxo32NHFKzmwgjJTmngK-0s1llV9F3XQXvGObyRnCxnyVbH4rKb8Z8DuB8yKQC7O0U6kdUF6KT0jLpITBV4SFf-UdF0QcixP6uXEe-MtGl3Xx8C5xE","e":"AQAB","kty":"RSA","n":"3LiaXfDj0Ohz0MRhz6fCNXOV6SDm2RAabJGWBk6NyII3HwdAkT9ToRrKnW2UzvlxegI9ZvtaJxiNS-V7Mfw4cQn3INVgRwTVfmRFUeZa40Kz0b3UeMIbppswoAUomRPwFMPJeHXXcqAWi2D7Z6BQlEIMTY4vKEg6jC93fPoLJCEKuwPRn7OAXIw9caWWOQsjTXrmKuYqLsPqAO49Am4IMm8uAX-RtCIl6fd9ZcI0CvBUbbTmJK3EkSpAxnQAwS-0FRYI-XK22SJz3YyeI0KVCsEARnBZajA4x8YhFK3ivcJ6Zs1cSDp67fj6g09RfYH6EteTb8gY5b7ARWme2MbyUw","p":"9rSy05qO-kNSPpb0emP8coeH2Fn61OSbBmq9x0vO4lmwPRSti3AMIo7qyRYuM0TgPXRAcbCxqsYo40eaabL5kR9nwb9qY52Gl3T8WlEsJW2Q1Mf0V0npzdB1qGlTOMCCkC4CQA6gRAE3cImZFb2y57FihWO4C1ouDNm6VPGwBKM","q":"5QlM1oLM2l1XMSTtA6USMN6TCJwI5W84nRI0mFe__zSenlYxVQy_jyIi8qiaW5TlOu_KoaplMAJl6zll5QanxNAU5vSlh5o3ckGClMPCkkM6X3_iIHNg8aNJ-qqTQiqLgKuCniqRus85avxumIAucCIBotiDqCVotOzhdAsthpE","qi":"izbMRPRkiZTNBFw-KufAz1_xnmoueuuG_-DnLg7kX8xj-yGW6fHXDQPxv0L4AHqGT_Vy7KotaUbxHaTmgszxjhGqrkzv-TeA5jfD6oVaKP9Lp4_YWUGMEcbmnQYTqBA2M_mAAqP8z77KNixtHCjcUdtV5kWKKco6sOHhWlmdNFM"}'
        token = b'{"payload":"HBE86DIy4RkTxwTxPrs3jR-_l3e9CNxBbMwgoJiGgVIEUKLWr50wIDZA0OnN24OcZmy_QNLbEs0dthHj_ddW5kefUTw5Eg","signatures":[{"protected":"eyJhbGciOiJFUzI1NiJ9","signature":"X9cMVGG1N-eze0Wd2vlx1GQXYEoxwytGjflswOOeh_oWuoNH_BOJpDPQ4yaMs_x_tiLEEF-gomnXV_per_6D2g"},{"protected":"eyJhbGciOiJIUzUxMiJ9","signature":"otWgkMW6aoH8hsHctvE6befp16TqAmiKZG_o6e8ZZ3mi2YjcSUfa0ZMxDMVW6r4MEhlifbq3ZBTQiMFzTobWpQ"},{"protected":"eyJhbGciOiJQUzUxMiJ9","signature":"jJT25xiDTd_kqlR06l8qZ20hkPnxSd5nszjWIF1PpkRLy2J3flYsxBM7KEogfQusO00-EBwqqtzUJ--_HW6w3L75Q_Hmn92UYL4dEqzOOR0iS_BeDuhc6GvOqJePaDxySlf9W2FL0M96_ldIMzGMeczsqB5OA3ziGRDLzCzlfHKNaUBH1zqWTkNza_t_ba9xeD-ewTFFX9cbM-2tSqPMVbIbip0gvMwO8b9-npCgbgb1x0s_IEvjmPfYYBKAxRUakQ9n-yBBFd--YqjO8FcoOZSc8cKPmxCdTVGf8PdV_PJbpkpofuHJOM2_VO--Z2S4uqCgj4URbnwBSPwSj7Ttww"}]}'

        jwsset = JWSSet.parse(token)

        ecdsa_key_a          = PKIAutoParser.import_key(key_a).key
        ecdsa_key_a.hash_obj = SHA256()

        self.assertTrue(jwsset.verify(ecdsa_key_a))
        self.assertTrue(jwsset.verify(JWKOctKey.decode(key_b).key))
        self.assertTrue(jwsset.verify(PKIAutoParser.import_key(key_c).key))
