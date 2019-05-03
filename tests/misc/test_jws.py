from samson.protocols.jwt.jws import JWS
from samson.protocols.jwt.jwa import JWASignatureAlg
from samson.public_key.rsa import RSA
from samson.public_key.ecdsa import ECDSA
from samson.utilities.bytes import Bytes
from samson.hashes.sha2 import SHA256, SHA384, SHA512
from fastecdsa.curve import P256, P384, P521
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
-----END PRIVATE KEY-----""")

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
-----END PRIVATE KEY-----""")

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
-----END PRIVATE KEY-----""")

ES1_KEY = ECDSA.import_key(b"""-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgpR4yjoqJ09GAriF++Pxu+I
O1FxF9uAGsniq77Lc6woehRANCAAQbdf1V9k89vTxPbWlzYoiJnk+RZpufb5AX7D4mRJN+
o0NjMxFrNFUyiq3Y7+wa9k06Lg7KL06HN+kaax2/Fp3M
-----END PRIVATE KEY-----""")

ES1_KEY.hash_obj = SHA256()

ES2_KEY = ECDSA.import_key(b"""-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDxg/XHeJj3sTTsO8Jnczsxzc
jLfwmbJlYMDg2SupAvsrck9iNktrlRlKDX3prWaquhZANiAASzOq9L0SGAfmP1NUxMKunV
mxF707SBdr17rYhes0Q+SpnQ7GWliRcGivg501bxcKxri6EIqPlTSstDmtgCPE7rowKVMt
jHB2itCKnpa4Zw6373AEe8xrxLrYvSlg1uPmw=
-----END PRIVATE KEY-----""")

ES2_KEY.hash_obj = SHA384()

ES3_KEY = ECDSA.import_key(b"""-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIB94Phb9b/eV0mEt4QHOLB/U
7r3bj1OodWCymrL3peOvkRSRmZqggZqXIUCOiPLLXelwEWeVaIo3zsR59nDiZ4EZqhgYkD
gYYABADYqohYc8LARgtRRE3XVKZ6oRduzHBhiemYBii196XaSSlsSqAApCEvdGzSJPOFMW
PeYxI1nnhsQEtveORMOp6j/QCWMbCkJkoz7q7iivE9i1y56Tm5G9CgqCxJ9mdjOnm0fE0n
bOsQ44F+Gb9beySSMIV3O9seMrQgZicBIKJ2uSx94w==
-----END PRIVATE KEY-----""")

ES3_KEY.hash_obj = SHA512()


BODY = json.dumps({
    "sub": "1234567890",
    "name": "John Doe",
    "iat": 1516239022
}).encode('utf-8')


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

# Tests generated from https://jws.io/
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
