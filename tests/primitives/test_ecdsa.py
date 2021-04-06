from samson.math.algebra.curves.named import P192, P224, P384, P256, P521
from samson.utilities.bytes import Bytes
from samson.public_key.ecdsa import ECDSA
from samson.encoding.general import PKIEncoding
from samson.encoding.pem import RFC1423Algorithms
from samson.hashes.sha1 import SHA1
from samson.hashes.sha2 import SHA224, SHA256, SHA384, SHA512
import json
import random
import unittest


# Generated using OpenSSL
# https://crypto.stackexchange.com/questions/50019/public-key-format-for-ecdsa-as-in-fips-186-4
# openssl ecparam -genkey -out testsk.pem -name prime256v1
# openssl ec -in testsk.pem -text
# openssl ec -in testsk.pem -pubout -text

TEST_PRIV = b"""-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFZQaZr7MxnTh2+gvCP+JDuWddZaH7JhCpkjZ8xVSGNgoAoGCCqGSM49
AwEHoUQDQgAE5bLfAOLXjroa/NMSBQ+xpUzBVK/yhfSkc0xXL82gIeT7HA1OT8zP
eGYg/FpbROz9w9iC+4h5lcvgR7Q7r+qFHQ==
-----END EC PRIVATE KEY-----"""

TEST_PUB = b"""-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5bLfAOLXjroa/NMSBQ+xpUzBVK/y
hfSkc0xXL82gIeT7HA1OT8zPeGYg/FpbROz9w9iC+4h5lcvgR7Q7r+qFHQ==
-----END PUBLIC KEY-----"""

EXPECTED_CURVE = P256
EXPECTED_PRIV  = 0x5650699afb3319d3876fa0bc23fe243b9675d65a1fb2610a992367cc55486360
EXPECTED_PUB   = Bytes(0xe5b2df00e2d78eba1afcd312050fb1a54cc154aff285f4a4734c572fcda021e4fb1c0d4e4fcccf786620fc5a5b44ecfdc3d882fb887995cbe047b43bafea851d)
PUB_POINT      = EXPECTED_CURVE(EXPECTED_PUB[:len(EXPECTED_PUB) // 2].int(), EXPECTED_PUB[len(EXPECTED_PUB) // 2:].int())


# openssl ecparam -genkey -out testsk521.pem -name secp521r1
TEST_PRIV_521 = b"""-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIAqj9wsNV/s+i0RFbY3Hcj0kkPWHpFpqexgPygAH/9pgd4zfl77qQH
6ytwc2KI/I9Q2m0W5xqpjXawagnwBigRxmOgBwYFK4EEACOhgYkDgYYABAA1ZdYy
HpsWrOnctAEeRia53sFSHhuZIID1oTrv0stwT4RlLT93/pvybEjyRDCVc40dT5gS
aFzSZ92LFXb8tdFf9AHUtKQCulKQFTk7aubPJv7UCxysMuIs6Lw9oPV+90VvGaGI
+yKcEagNS++ASqYNqMPzRcjjWaL/EIBhB+auMcT1Pw==
-----END EC PRIVATE KEY-----
"""

TEST_PUB_521 = b"""-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQANWXWMh6bFqzp3LQBHkYmud7BUh4b
mSCA9aE679LLcE+EZS0/d/6b8mxI8kQwlXONHU+YEmhc0mfdixV2/LXRX/QB1LSk
ArpSkBU5O2rmzyb+1AscrDLiLOi8PaD1fvdFbxmhiPsinBGoDUvvgEqmDajD80XI
41mi/xCAYQfmrjHE9T8=
-----END PUBLIC KEY-----"""


EXPECTED_CURVE_521 = P521
EXPECTED_PRIV_521  = 0x00aa3f70b0d57fb3e8b44456d8dc7723d2490f587a45a6a7b180fca0007ffda60778cdf97beea407eb2b70736288fc8f50da6d16e71aa98d76b06a09f0062811c663
EXPECTED_PUB_521   = Bytes(0x003565d6321e9b16ace9dcb4011e4626b9dec1521e1b992080f5a13aefd2cb704f84652d3f77fe9bf26c48f2443095738d1d4f9812685cd267dd8b1576fcb5d15ff401d4b4a402ba529015393b6ae6cf26fed40b1cac32e22ce8bc3da0f57ef7456f19a188fb229c11a80d4bef804aa60da8c3f345c8e359a2ff10806107e6ae31c4f53f)
PUB_POINT_521      = EXPECTED_CURVE_521(EXPECTED_PUB_521[:len(EXPECTED_PUB_521) // 2].int(), EXPECTED_PUB_521[len(EXPECTED_PUB_521) // 2:].int())



# ssh-keygen -t ecdsa -f test_ecdsa_ssh
# ssh-keygen -e -f test_ecdsa_ssh
TEST_SSH_PRIV = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQTfqIzzQ2SjHfSujA1qJUGAPEBuU4Ok
wZUEe4Pz5/LBbbXZY4tEHgGIqLPVDgiSNVTWak6DtXHmui/mBIe+qsKHAAAAsOjVMFLo1T
BSAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN+ojPNDZKMd9K6M
DWolQYA8QG5Tg6TBlQR7g/Pn8sFttdlji0QeAYios9UOCJI1VNZqToO1cea6L+YEh76qwo
cAAAAgSp/lGR7Bd1KDs7UkH/hOlSeYd7LYK0WXChm0Md3Gk6YAAAARZG9uYWxkQERvbmFs
ZC1NQlABAgMEBQYH
-----END OPENSSH PRIVATE KEY-----"""


TEST_SSH_PUB = b"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN+ojPNDZKMd9K6MDWolQYA8QG5Tg6TBlQR7g/Pn8sFttdlji0QeAYios9UOCJI1VNZqToO1cea6L+YEh76qwoc= nohost@localhost"

TEST_SSH2_PUB = b"""---- BEGIN SSH2 PUBLIC KEY ----
Comment: "256-bit ECDSA, converted by nohost@localhost from OpenSSH"
AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN+ojPNDZKMd9K6MDW
olQYA8QG5Tg6TBlQR7g/Pn8sFttdlji0QeAYios9UOCJI1VNZqToO1cea6L+YEh76qwoc=

---- END SSH2 PUBLIC KEY ----"""


TEST_SSH2_PUB_NO_CMT = b"""---- BEGIN SSH2 PUBLIC KEY ----
AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN+ojPNDZKMd9K6MDW
olQYA8QG5Tg6TBlQR7g/Pn8sFttdlji0QeAYios9UOCJI1VNZqToO1cea6L+YEh76qwoc=

---- END SSH2 PUBLIC KEY ----"""

# Generated using ssh-keygen and OpenSSL
# ssh-keygen -t ecdsa -N 'super secret passphrase' -f test_ecdsa_key -m PEM
# openssl ec -aes192 -in test_ecdsa_key -text
# openssl ec -aes256 -in test_ecdsa_key -text
# openssl ec -des -in test_ecdsa_key -text
# openssl ec -des3 -in test_ecdsa_key -text

PEM_PASSPHRASE = b"super secret passphrase"

TEST_PEM_DEC = b"""-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHIDLVo4s+FzBR/XmlHzsyQPbYn5Auwa14FVmF3J4FwEoAoGCCqGSM49
AwEHoUQDQgAEiqvr5mACJTTYbhGHdrlnJ5SxrnfalYZwmHDQGdMKQVeR1hXqgsnb
AjlQB0m9alO1rG3EWYhaIfW9BwxNxIHK1g==
-----END EC PRIVATE KEY-----"""


TEST_PEM_AES_128_ENC = b"""-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,C981702945DB6FAD288A670F0B67A833

l7lGdhS7i18L61l1Q7W6lmCbYDuH4Zzp7iWHvL7vzvYzZRSq6eNK9z/Td2bNIlpD
z4/PHEpTV8zzypNe8m3XX/TGkYhkvjDHFCZkoAJnaoQ6fxQbgQkGx24VmC7NzbT4
28y+qoN4SYNGWTY6wumOPtvYn5Tkn5kCeBB5nkVXJF4=
-----END EC PRIVATE KEY-----"""


TEST_PEM_AES_192_ENC = b"""-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-192-CBC,F0A40CF0E5F716A03D621AD30BC392D0

OrfXpDFVSVF/AqGMvjCrnZzC2IPBJ9w08/fojpIU7xoS/b86oIEqLXHtI8x0uTgD
5BTGzeHIk5XxflJL5fca+DYH6OoQ6ABN35vhh4stdt4ap+zleZBjwRK9O27PHkV4
5CzrnfPhooAQS8C4iKJ8zP+K7BkqkiPengNqFIGXHlM=
-----END EC PRIVATE KEY-----"""


TEST_PEM_AES_256_ENC = b"""-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,C85939A34BB07379720B08A854C5485C

mK4SmlFb/BbnKC5ZItMN4+1p4E6/5VNzivEd0KDBnRwJ5FJ0pKpDkNTbtLj/Ztql
BI2nOK9LQ58SNbnM7fgXPWI8QGJtRoo05wTLx0+suK1zOzeFQ72CB9pWBSByWM8E
M/T+9PtZ49bTwfjuj/cmcDZyWGT2TKXai8n2Eic0MiE=
-----END EC PRIVATE KEY-----"""


TEST_PEM_DES_ENC = b"""-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-CBC,6EB0EFD0E559CD57

gJwuXc1Io97tGeS0gJIjKanNNXzvXpTpa3r4GbK8o91DTQ03PXjNXBYP/gxEJ+eM
4RCAs/AyTchgjq2vdeQKuQuVD7VteENDjPQJ8J/w5Q9OTI0E1M/VCjhNwN2ofGbQ
XRTAw1AavOgJZGXDMQOTHBDCXDYO4+dCVzQy7m81E4s=
-----END EC PRIVATE KEY-----"""


TEST_PEM_DES3_ENC = b"""-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,097889AD025D4FDA

/eLyDjyHEfpikTayfUHtJMCXwEyXamDz9YbW35j3WedHEul2O5WaPhTTSFlMcEgX
CaXCb5kuNb86emoAZmzmzgJ7vf5paX/sXptxZvLu8TVnL9mGd4J4WJngW6OtJjFc
ekSjuWil8PH9HSA7HnBcS5LKwaHEaHuBTSbSyJWuW1c=
-----END EC PRIVATE KEY-----"""


# ssh-keygen -t ecdsa -f ssh0
# ssh-keygen -t ecdsa -f ssh1
# ssh-keygen -t ecdsa -f ssh2 -N '33754c0f43c12ca5'
# ssh-keygen -t ecdsa -f ssh3 -N '692fe1e040f63bcc'

TEST_OPENSSH0 = (b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQT3OKW55K928fgS959zJKt7vxjZa325
AhqK2DsgfgrL7PCOR8sHKVBAVSoYqgL2quD1/a0nQInT6iKdHjt2eJFKAAAAsEfqLHVH6i
x1AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPc4pbnkr3bx+BL3
n3Mkq3u/GNlrfbkCGorYOyB+Csvs8I5HywcpUEBVKhiqAvaq4PX9rSdAidPqIp0eO3Z4kU
oAAAAhAMV8Z+6PWs8S6h/LzKVq1iZSLo8KMttO6ZhJJPT1P28HAAAAEWRvbmFsZEBEb25h
bGQtTUJQAQIDBAUG
-----END OPENSSH PRIVATE KEY-----""", None)

TEST_OPENSSH1 = (b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQTR6THrFlIzWynLXARNN9Oq2EBtbn8X
VCg25Jc/ysOlSlVzMAi9Wl8Q0/sESsBHbcWb8iQEixfPiQr7K8BvF7akAAAAsKNI90qjSP
dKAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNHpMesWUjNbKctc
BE0306rYQG1ufxdUKDbklz/Kw6VKVXMwCL1aXxDT+wRKwEdtxZvyJASLF8+JCvsrwG8Xtq
QAAAAhAJNY2X8nRWJQU4XCR8sUa06h4GaSVgUK5pKUtGJM1UypAAAAEWRvbmFsZEBEb25h
bGQtTUJQAQIDBAUG
-----END OPENSSH PRIVATE KEY-----""", None)

TEST_OPENSSH2 = (b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCi2rSY/6
XvIos8XrmthE1LAAAAEAAAAAEAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz
dHAyNTYAAABBBK1fTBfZ3fZeXnYHo0JbD0rL8XU5JKju7BY8oRvr08UeJf9LJh47+yqe2/
PxwR7jywJ5C6KO+Kq1hGoqSJ4IrzoAAACww1spwnk50Oe+ooaFM6m8g2uKlJsRUbSLqejX
uHv21CgYgANaTRQpn26xl9yBjW3MUCG8tMfJz9UYJ+mWXs/gF6ook5mgOUrErTnixvi4Uj
9r6Ck6EgKWOfvv252bDmi5nq8bp9VKjtcHQfN/5qrFK9+TjmoRvTzerJA+OnYRHcr22lw8
oM8u5kVMo1AIFEv7ls+GFvrGfGcc6iuCpCi5BtZzNHwh432uRxygoqY4+xg=
-----END OPENSSH PRIVATE KEY-----""", b'33754c0f43c12ca5')

TEST_OPENSSH3 = (b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCSksZFhw
lOiMWgdIYM4keoAAAAEAAAAAEAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz
dHAyNTYAAABBBBD9lJaJ2GFI6rAPlAwXmOtWbZ3Kdvj2WMn4UkxZrOVCgmYDpBRWsxM8sy
/WOadTMGce7s2KqB6UbU9TET8N5DoAAACwS6YYv9PfxO0SSMxRS/yfMYn+DhJVMHn2z27o
c6Sbw0iKcvHyB3NbOJF19bPMDr63t3WxW+F4lJbR+z0KMrgzvf0hlg1Sfj8i4Es9BPcH22
aOdbIEH+BasBrC0jhiaCvHI2NNxdVkP8a6kfwzpPSCNc+LpIlqTjVTlZKRUKTvvs5pjqZ/
ZvlicyXNaRi6YZYwy6myBHPkZ3r7jjpF+CrAFZsF17q+mBSRn6swmt9P7Sw=
-----END OPENSSH PRIVATE KEY-----""", b'692fe1e040f63bcc')


# JWK example from https://tools.ietf.org/html/rfc7517#section-3
TEST_JWK = b'{"kty": "EC", "crv": "P-256", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}'

# Generated from https://mkjwk.org/
TEST_JWK_PRIV = b'{"kty": "EC", "d": "wGybSwZmblxJ7LUlIc7gB9f2-pHIsXLRXoY-J7VouKE", "use": "sig", "crv": "P-256", "x": "IiF1LRHbsKruh0OY-HYPQGwdKowBoV8fKlPcAzqS774", "y": "n2PCpTDDdZloPtxmajIogALMl8TkRfIm7I4rF3wHv9U", "alg": "ES256"}'

# openssl ecparam -name secp521r1 -genkey -param_enc explicit -out private-key.pem
# openssl req -new -x509 -key private-key.pem -out server.pem -days 730
TEST_X509_CERT_EXPLICIT = b"""-----BEGIN CERTIFICATE-----
MIIEQjCCA6OgAwIBAgIJAL9UTkR+Sat+MAoGCCqGSM49BAMCMFcxCzAJBgNVBAYT
AlVTMRUwEwYDVQQHDAxEZWZhdWx0IENpdHkxHDAaBgNVBAoME0RlZmF1bHQgQ29t
cGFueSBMdGQxEzARBgNVBAMMCndoYXR0YWNlcnQwHhcNMTkwMzA0MjI1NTQyWhcN
MjEwMzAzMjI1NTQyWjBXMQswCQYDVQQGEwJVUzEVMBMGA1UEBwwMRGVmYXVsdCBD
aXR5MRwwGgYDVQQKDBNEZWZhdWx0IENvbXBhbnkgTHRkMRMwEQYDVQQDDAp3aGF0
dGFjZXJ0MIICXDCCAc8GByqGSM49AgEwggHCAgEBME0GByqGSM49AQECQgH/////
////////////////////////////////////////////////////////////////
/////////////////zCBngRCAf//////////////////////////////////////
///////////////////////////////////////////////8BEFRlT65YY4cmh+S
miGgtoVA7qLacluZsxXzuLSJkY7xCeFWGTlR7H6TexZSwL07sb8HNXPfiD0sNPHv
RR/Ua1A/AAMVANCeiAApHLhTlsxnFzkyhKqg2mS6BIGFBADGhY4GtwQE6c2ePstm
I5W0QpxkgTkFP7Uh+CivYGtNPbqhS1537+dZKP4dwSei/6jeM0izwYVqQpv5fn4x
wuW9ZgEYOSlqeJo7wARcil+0LH0b2Zj1RElXm0RoF6+9Fyc+ZiyX7nKZXvQmQMVQ
uQE/rQdhNTxwhqJywkCIvpR2n9FmUAJCAf//////////////////////////////
////////////+lGGh4O/L5Zrf8wBSPcJpdA7tcm4iZxHrrtvtx6ROGQJAgEBA4GG
AAQAvn56JdELJRSZMVIdh/7v+6JGeBwVbAXEl0lcc5HGefBhoLl7eA6DE0raufmo
o9PBWGoucNTKxu9LS9aEiZBsRBEAfDx2Ip7BcSFv6xGHziNsKe73yactANS/v7Hh
pKi6qCqmHF5w3Hi0AIE9aSpeBmVm8pmyJOcszjN0CIXDQapvSAajUzBRMB0GA1Ud
DgQWBBSFKqSyTnvMG0lU8hHHby1wpzgjVjAfBgNVHSMEGDAWgBSFKqSyTnvMG0lU
8hHHby1wpzgjVjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA4GMADCBiAJC
AWUXPGWi8q5u87XVNQ+RwDHKvDfqsktfxLk9IsJoDW9qltTvHGC+p8JV4mcbbQfc
xRco5gwHlfLQbzHdAnF7QDZAAkIBadKWqL3qYQZswfWHThya7LbuMH6otTTL6fzW
4JwatM3iGhTXB44I5FC0NR+aTVW3TGFhSQJmQszxgXhsAzh2V08=
-----END CERTIFICATE-----"""


TEST_X509_CERT = b"""-----BEGIN CERTIFICATE-----
MIICVTCCAbegAwIBAgIJAObYauBtx7ErMAoGCCqGSM49BAMCMEIxCzAJBgNVBAYT
AlVTMRUwEwYDVQQHDAxEZWZhdWx0IENpdHkxHDAaBgNVBAoME0RlZmF1bHQgQ29t
cGFueSBMdGQwHhcNMTkwMzA2MjE0MDU0WhcNMjEwMzA1MjE0MDU0WjBCMQswCQYD
VQQGEwJVUzEVMBMGA1UEBwwMRGVmYXVsdCBDaXR5MRwwGgYDVQQKDBNEZWZhdWx0
IENvbXBhbnkgTHRkMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQANWXWMh6bFqzp
3LQBHkYmud7BUh4bmSCA9aE679LLcE+EZS0/d/6b8mxI8kQwlXONHU+YEmhc0mfd
ixV2/LXRX/QB1LSkArpSkBU5O2rmzyb+1AscrDLiLOi8PaD1fvdFbxmhiPsinBGo
DUvvgEqmDajD80XI41mi/xCAYQfmrjHE9T+jUzBRMB0GA1UdDgQWBBRmpRseBj0D
ybJF+rxlfd79MSY+3TAfBgNVHSMEGDAWgBRmpRseBj0DybJF+rxlfd79MSY+3TAP
BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA4GLADCBhwJBUxtG7EgaBBJlpXo9
xhF5tgd4wEHMZbrtfkp4/0LBHYDz+bifFchqK5o1+t7epNt8zBqjfan59rUSKWKX
60ed+PYCQgE1m+Jq6SUjoQRBA9+TMsNJh7w+dpLp+gNnLrKCOStsLiq3or0yiyE/
GAaGuoXhVJxq9PmRV8ccmKIXNDI2bEHkUw==
-----END CERTIFICATE-----"""


TEST_X509 = b"""-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQANWXWMh6bFqzp3LQBHkYmud7BUh4b
mSCA9aE679LLcE+EZS0/d/6b8mxI8kQwlXONHU+YEmhc0mfdixV2/LXRX/QB1LSk
ArpSkBU5O2rmzyb+1AscrDLiLOi8PaD1fvdFbxmhiPsinBGoDUvvgEqmDajD80XI
41mi/xCAYQfmrjHE9T8=
-----END PUBLIC KEY-----"""


TEST_PKCS8 = b"""-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAqj9wsNV/s+i0RFbY
3Hcj0kkPWHpFpqexgPygAH/9pgd4zfl77qQH6ytwc2KI/I9Q2m0W5xqpjXawagnw
BigRxmOhgYkDgYYABAA1ZdYyHpsWrOnctAEeRia53sFSHhuZIID1oTrv0stwT4Rl
LT93/pvybEjyRDCVc40dT5gSaFzSZ92LFXb8tdFf9AHUtKQCulKQFTk7aubPJv7U
CxysMuIs6Lw9oPV+90VvGaGI+yKcEagNS++ASqYNqMPzRcjjWaL/EIBhB+auMcT1
Pw==
-----END PRIVATE KEY-----"""


class ECDSATestCase(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None

    def test_k_derivation(self):
        ecdsa = ECDSA(P256.G)
        k = Bytes.random(32).int()
        msgA = b'my first message'
        msgB = b'uh oh, two messages?!'

        sigA = ecdsa.sign(msgA, k)
        sigB = ecdsa.sign(msgB, k)

        found_k = ecdsa.derive_k_from_sigs(msgA, sigA, msgB, sigB)
        self.assertEqual(found_k, k)

        d = ecdsa.d
        self.assertEqual(ecdsa.derive_x_from_k(msgA, found_k, sigA), d)


    def test_import_export_private(self):
        ecdsa     = ECDSA.import_key(TEST_PRIV).key
        der_bytes = ecdsa.export_private_key(encoding=PKIEncoding.PKCS1).encode()
        new_ecdsa = ECDSA.import_key(der_bytes).key

        self.assertEqual((ecdsa.G, ecdsa.d, ecdsa.Q), (new_ecdsa.G, new_ecdsa.d, new_ecdsa.Q))
        self.assertEqual((ecdsa.G.curve, ecdsa.d, ecdsa.Q), (EXPECTED_CURVE, EXPECTED_PRIV, PUB_POINT))
        self.assertEqual(der_bytes.replace(b'\n', b''), TEST_PRIV.replace(b'\n', b''))


    def test_import_export_private_521(self):
        ecdsa     = ECDSA.import_key(TEST_PRIV_521).key
        der_bytes = ecdsa.export_private_key(encoding=PKIEncoding.PKCS1).encode()
        new_ecdsa = ECDSA.import_key(der_bytes).key

        self.assertEqual((ecdsa.G, ecdsa.d, ecdsa.Q), (new_ecdsa.G, new_ecdsa.d, new_ecdsa.Q))
        self.assertEqual((ecdsa.G.curve, ecdsa.d, ecdsa.Q), (EXPECTED_CURVE_521, EXPECTED_PRIV_521, PUB_POINT_521))
        self.assertEqual(der_bytes.replace(b'\n', b''), TEST_PRIV_521.replace(b'\n', b''))



    def test_import_export_public(self):
        ecdsa_pub  = ECDSA.import_key(TEST_PUB).key
        ecdsa_priv = ECDSA.import_key(TEST_PRIV).key

        der_bytes = ecdsa_pub.export_public_key(encoding=PKIEncoding.X509).encode()
        new_pub  = ECDSA.import_key(der_bytes).key

        self.assertEqual(ecdsa_pub.Q, ecdsa_priv.Q)
        self.assertEqual(new_pub.Q, ecdsa_priv.Q)
        self.assertEqual(der_bytes.replace(b'\n', b''), TEST_PUB.replace(b'\n', b''))



    def _run_import_pem_enc(self, enc_priv):
        with self.assertRaises(ValueError):
            ECDSA.import_key(enc_priv).key

        enc_ecdsa = ECDSA.import_key(enc_priv, PEM_PASSPHRASE).key
        dec_ecdsa = ECDSA.import_key(TEST_PEM_DEC).key
        self.assertEqual((enc_ecdsa.G, enc_ecdsa.d, enc_ecdsa.Q), (dec_ecdsa.G, dec_ecdsa.d, dec_ecdsa.Q))


    def test_import_enc_aes_128(self):
        self._run_import_pem_enc(TEST_PEM_AES_128_ENC)

    def test_import_enc_aes_192(self):
        self._run_import_pem_enc(TEST_PEM_AES_192_ENC)

    def test_import_enc_aes_256(self):
        self._run_import_pem_enc(TEST_PEM_AES_256_ENC)

    def test_import_enc_des(self):
        self._run_import_pem_enc(TEST_PEM_DES_ENC)

    def test_import_enc_des3(self):
        self._run_import_pem_enc(TEST_PEM_DES3_ENC)


    def test_import_enc_gauntlet(self):
        for algo in RFC1423Algorithms:
            for _ in range(10):
                ecdsa     = ECDSA(G=P256.G, hash_obj=None)
                key       = Bytes.random(Bytes.random(1).int() + 1)
                enc_pem   = ecdsa.export_private_key(encryption=algo, passphrase=key).encode()
                dec_ecdsa = ECDSA.import_key(enc_pem, key).key

                self.assertEqual((ecdsa.G, ecdsa.d, ecdsa.Q), (dec_ecdsa.G, dec_ecdsa.d, dec_ecdsa.Q))



    def test_import_ssh(self):
        ecdsa_pub      = ECDSA.import_key(TEST_SSH_PUB).key
        ecdsa_ssh2_pub = ECDSA.import_key(TEST_SSH2_PUB).key
        ecdsa_priv     = ECDSA.import_key(TEST_SSH_PRIV).key

        self.assertEqual((ecdsa_pub.G, ecdsa_pub.Q), (ecdsa_priv.G, ecdsa_priv.Q))
        self.assertEqual((ecdsa_ssh2_pub.G, ecdsa_ssh2_pub.Q), (ecdsa_priv.G, ecdsa_priv.Q))
        self.assertEqual(ecdsa_priv.d * ecdsa_priv.G, ecdsa_priv.Q)

        self.assertEqual(ecdsa_pub.export_public_key(encoding=PKIEncoding.OpenSSH).encode().replace(b'\n', b''), TEST_SSH_PUB.replace(b'\n', b''))
        self.assertEqual(ecdsa_ssh2_pub.export_public_key(encoding=PKIEncoding.SSH2).encode().replace(b'\n', b''), TEST_SSH2_PUB_NO_CMT.replace(b'\n', b''))



    def test_import_openssh(self):
        for key, passphrase in [TEST_OPENSSH0, TEST_OPENSSH1, TEST_OPENSSH2, TEST_OPENSSH3]:
            if passphrase:
                with self.assertRaises(ValueError):
                    ECDSA.import_key(key).key

            ecdsa = ECDSA.import_key(key, passphrase=passphrase).key
            self.assertEqual(ecdsa.d * ecdsa.G, ecdsa.Q)
            self.assertLess(ecdsa.d, ecdsa.q)



    def test_openssh_gauntlet(self):
        num_runs = 6
        num_enc  = num_runs // 3
        curves   = [P192, P224, P256, P384, P521]

        for i in range(num_runs):
            curve = random.choice(curves)
            ecdsa = ECDSA(curve.G)
            passphrase = None


            if i < num_enc:
                passphrase = Bytes.random(Bytes.random(1).int())

            priv        = ecdsa.export_private_key(encoding=PKIEncoding.OpenSSH).encode(encryption=b'aes256-ctr', passphrase=passphrase)
            pub_openssh = ecdsa.export_public_key(encoding=PKIEncoding.OpenSSH).encode()
            pub_ssh2    = ecdsa.export_public_key(encoding=PKIEncoding.SSH2).encode()

            new_priv         = ECDSA.import_key(priv, passphrase=passphrase).key
            new_pub_openssh  = ECDSA.import_key(pub_openssh).key
            new_pub_ssh2     = ECDSA.import_key(pub_ssh2).key

            self.assertEqual((new_priv.d, new_priv.G, new_priv.Q), (ecdsa.d, ecdsa.G, ecdsa.Q))
            self.assertEqual((new_pub_openssh.G, new_pub_openssh.Q), (ecdsa.G, ecdsa.Q))
            self.assertEqual((new_pub_ssh2.G, new_pub_ssh2.Q), (ecdsa.G, ecdsa.Q))


    def test_import_jwk(self):
        ec = ECDSA.import_key(TEST_JWK).key
        jwk = ec.export_public_key(encoding=PKIEncoding.JWK).encode()
        self.assertEqual(jwk, TEST_JWK)

        ec  = ECDSA.import_key(TEST_JWK_PRIV).key
        jwk = ec.export_private_key(encoding=PKIEncoding.JWK).encode()

        as_dict = json.loads(TEST_JWK_PRIV.decode())
        del as_dict['use']
        del as_dict['alg']

        self.assertEqual(json.loads(jwk.decode()), as_dict)



    def test_jwk_gauntlet(self):
        curves = [P192, P224, P256, P384, P521]
        for _ in range(100):
            curve = random.choice(curves)
            ecdsa = ECDSA(curve.G)

            priv = ecdsa.export_private_key(encoding=PKIEncoding.JWK).encode()
            pub  = ecdsa.export_public_key(encoding=PKIEncoding.JWK).encode()

            new_priv = ECDSA.import_key(priv).key
            new_pub  = ECDSA.import_key(pub).key

            self.assertEqual((new_priv.d, new_priv.G, new_priv.Q), (ecdsa.d, ecdsa.G, ecdsa.Q))
            self.assertEqual((new_pub.G, new_pub.Q), (ecdsa.G, ecdsa.Q))


    def test_import_x509_cert(self):
        from subprocess import check_call

        cert = ECDSA.import_key(TEST_X509_CERT)
        ec   = cert.key
        self.assertEqual((ec.Q.x, ec.Q.y), (715947441162623524308031264370421599762967653523544747480787993496487140462283488974903669322082866021662891001767126467535751404779526256673589715857924084, 6284315030597594553103397980681739738230677011801289227519057103940802676199779900446162742685830902816710685363967012731548834638923262185574277733031408959))

        # .export_public_key(encoding=PKIEncoding.X509_CERT)
        cert = cert.encode().decode()
        check_call([f'echo -n \"{cert}\" | openssl x509 -text'], shell=True)



    def test_import_x509(self):
        ec = ECDSA.import_key(TEST_X509).key
        ec_bytes = ec.export_public_key(encoding=PKIEncoding.X509).encode()
        self.assertEqual((ec.Q.x, ec.Q.y), (715947441162623524308031264370421599762967653523544747480787993496487140462283488974903669322082866021662891001767126467535751404779526256673589715857924084, 6284315030597594553103397980681739738230677011801289227519057103940802676199779900446162742685830902816710685363967012731548834638923262185574277733031408959))
        self.assertEqual(ec_bytes.replace(b'\n', b''), TEST_X509.replace(b'\n', b''))



    def test_import_pkcs8(self):
        ec       = ECDSA.import_key(TEST_PKCS8).key
        ec_bytes = ec.export_private_key(encoding=PKIEncoding.PKCS8).encode()

        self.assertEqual(ec.d, 2282649980877248464928985540593193992740494509534471044083643023670157012821680477618689736007052097550343217684448593053345246736083446705198105618319263331)
        self.assertEqual((ec.Q.x, ec.Q.y), (715947441162623524308031264370421599762967653523544747480787993496487140462283488974903669322082866021662891001767126467535751404779526256673589715857924084, 6284315030597594553103397980681739738230677011801289227519057103940802676199779900446162742685830902816710685363967012731548834638923262185574277733031408959))
        self.assertEqual(ec_bytes.replace(b'\n', b''), TEST_PKCS8.replace(b'\n', b''))



    # https://tools.ietf.org/html/rfc6979#appendix-A.2.5
    def _run_test(self, curve, x, message, H, k, expected_sig):
        ecdsa = ECDSA(curve.G, H, d=x)
        r,s   = ecdsa.sign(message, k=k)
        sig   = (int(r), int(s))

        self.assertEqual(sig, expected_sig)
        self.assertTrue(ecdsa.verify(message, sig))


    def _run_192(self, message, H, k, expected_sig):
        curve = P192
        x = 0x6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4

        self._run_test(curve, x, message, H, k, expected_sig)


    def _run_224(self, message, H, k, expected_sig):
        curve = P224
        x = 0xF220266E1105BFE3083E03EC7A3A654651F45E37167E88600BF257C1

        self._run_test(curve, x, message, H, k, expected_sig)


    def _run_256(self, message, H, k, expected_sig):
        curve = P256
        x = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721

        self._run_test(curve, x, message, H, k, expected_sig)


    def _run_521(self, message, H, k, expected_sig):
        curve = P521
        x = 0x0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538

        self._run_test(curve, x, message, H, k, expected_sig)



    def test_vec0(self):
        message = b'sample'
        H = SHA1()
        k = 0x37D7CA00D2C7B0E5E412AC03BD44BA837FDD5B28CD3B0021
        r = 0x98C6BD12B23EAF5E2A2045132086BE3EB8EBD62ABF6698FF
        s = 0x57A22B07DEA9530F8DE9471B1DC6624472E8E2844BC25B64

        self._run_192(message, H, k, (r, s))


    def test_vec1(self):
        message = b'sample'
        H = SHA224()
        k = 0x4381526B3FC1E7128F202E194505592F01D5FF4C5AF015D8
        r = 0xA1F00DAD97AEEC91C95585F36200C65F3C01812AA60378F5
        s = 0xE07EC1304C7C6C9DEBBE980B9692668F81D4DE7922A0F97A

        self._run_192(message, H, k, (r, s))


    def test_vec2(self):
        message = b'sample'
        H = SHA256()
        k = 0x32B1B6D7D42A05CB449065727A84804FB1A3E34D8F261496
        r = 0x4B0B8CE98A92866A2820E20AA6B75B56382E0F9BFD5ECB55
        s = 0xCCDB006926EA9565CBADC840829D8C384E06DE1F1E381B85

        self._run_192(message, H, k, (r, s))


    def test_vec3(self):
        message = b'sample'
        H = SHA384()
        k = 0x4730005C4FCB01834C063A7B6760096DBE284B8252EF4311
        r = 0xDA63BF0B9ABCF948FBB1E9167F136145F7A20426DCC287D5
        s = 0xC3AA2C960972BD7A2003A57E1C4C77F0578F8AE95E31EC5E

        self._run_192(message, H, k, (r, s))


    def test_vec4(self):
        message = b'sample'
        H = SHA512()
        k = 0xA2AC7AB055E4F20692D49209544C203A7D1F2C0BFBC75DB1
        r = 0x4D60C5AB1996BD848343B31C00850205E2EA6922DAC2E4B8
        s = 0x3F6E837448F027A1BF4B34E796E32A811CBB4050908D8F67

        self._run_192(message, H, k, (r, s))


    def test_vec5(self):
        message = b'test'
        H = SHA1()
        k = 0xD9CF9C3D3297D3260773A1DA7418DB5537AB8DD93DE7FA25
        r = 0x0F2141A0EBBC44D2E1AF90A50EBCFCE5E197B3B7D4DE036D
        s = 0xEB18BC9E1F3D7387500CB99CF5F7C157070A8961E38700B7

        self._run_192(message, H, k, (r, s))


    def test_vec6(self):
        message = b'test'
        H = SHA224()
        k = 0xF5DC805F76EF851800700CCE82E7B98D8911B7D510059FBE
        r = 0x6945A1C1D1B2206B8145548F633BB61CEF04891BAF26ED34
        s = 0xB7FB7FDFC339C0B9BD61A9F5A8EAF9BE58FC5CBA2CB15293

        self._run_192(message, H, k, (r, s))


    def test_vec7(self):
        message = b'test'
        H = SHA256()
        k = 0x5C4CE89CF56D9E7C77C8585339B006B97B5F0680B4306C6C
        r = 0x3A718BD8B4926C3B52EE6BBE67EF79B18CB6EB62B1AD97AE
        s = 0x5662E6848A4A19B1F1AE2F72ACD4B8BBE50F1EAC65D9124F

        self._run_192(message, H, k, (r, s))


    def test_vec8(self):
        message = b'test'
        H = SHA384()
        k = 0x5AFEFB5D3393261B828DB6C91FBC68C230727B030C975693
        r = 0xB234B60B4DB75A733E19280A7A6034BD6B1EE88AF5332367
        s = 0x7994090B2D59BB782BE57E74A44C9A1C700413F8ABEFE77A

        self._run_192(message, H, k, (r, s))



    def test_vec9(self):
        message = b'test'
        H = SHA512()
        k = 0x0758753A5254759C7CFBAD2E2D9B0792EEE44136C9480527
        r = 0xFE4F4AE86A58B6507946715934FE2D8FF9D95B6B098FE739
        s = 0x74CF5605C98FBA0E1EF34D4B5A1577A7DCF59457CAE52290

        self._run_192(message, H, k, (r, s))



    def test_vec10(self):
        message = b'sample'
        H = SHA1()
        k = 0x7EEFADD91110D8DE6C2C470831387C50D3357F7F4D477054B8B426BC
        r = 0x22226F9D40A96E19C4A301CE5B74B115303C0F3A4FD30FC257FB57AC
        s = 0x66D1CDD83E3AF75605DD6E2FEFF196D30AA7ED7A2EDF7AF475403D69

        self._run_224(message, H, k, (r, s))


    def test_vec11(self):
        message = b'sample'
        H = SHA224()
        k = 0xC1D1F2F10881088301880506805FEB4825FE09ACB6816C36991AA06D
        r = 0x1CDFE6662DDE1E4A1EC4CDEDF6A1F5A2FB7FBD9145C12113E6ABFD3E
        s = 0xA6694FD7718A21053F225D3F46197CA699D45006C06F871808F43EBC

        self._run_224(message, H, k, (r, s))


    def test_vec12(self):
        message = b'sample'
        H = SHA256()
        k = 0xAD3029E0278F80643DE33917CE6908C70A8FF50A411F06E41DEDFCDC
        r = 0x61AA3DA010E8E8406C656BC477A7A7189895E7E840CDFE8FF42307BA
        s = 0xBC814050DAB5D23770879494F9E0A680DC1AF7161991BDE692B10101

        self._run_224(message, H, k, (r, s))


    def test_vec13(self):
        message = b'sample'
        H = SHA384()
        k = 0x52B40F5A9D3D13040F494E83D3906C6079F29981035C7BD51E5CAC40
        r = 0x0B115E5E36F0F9EC81F1325A5952878D745E19D7BB3EABFABA77E953
        s = 0x830F34CCDFE826CCFDC81EB4129772E20E122348A2BBD889A1B1AF1D

        self._run_224(message, H, k, (r, s))


    def test_vec14(self):
        message = b'sample'
        H = SHA512()
        k = 0x9DB103FFEDEDF9CFDBA05184F925400C1653B8501BAB89CEA0FBEC14
        r = 0x074BD1D979D5F32BF958DDC61E4FB4872ADCAFEB2256497CDAC30397
        s = 0xA4CECA196C3D5A1FF31027B33185DC8EE43F288B21AB342E5D8EB084

        self._run_224(message, H, k, (r, s))


    def test_vec15(self):
        message = b'test'
        H = SHA1()
        k = 0x2519178F82C3F0E4F87ED5883A4E114E5B7A6E374043D8EFD329C253
        r = 0xDEAA646EC2AF2EA8AD53ED66B2E2DDAA49A12EFD8356561451F3E21C
        s = 0x95987796F6CF2062AB8135271DE56AE55366C045F6D9593F53787BD2

        self._run_224(message, H, k, (r, s))


    def test_vec16(self):
        message = b'test'
        H = SHA224()
        k = 0xDF8B38D40DCA3E077D0AC520BF56B6D565134D9B5F2EAE0D34900524
        r = 0xC441CE8E261DED634E4CF84910E4C5D1D22C5CF3B732BB204DBEF019
        s = 0x902F42847A63BDC5F6046ADA114953120F99442D76510150F372A3F4

        self._run_224(message, H, k, (r, s))


    def test_vec17(self):
        message = b'test'
        H = SHA256()
        k = 0xFF86F57924DA248D6E44E8154EB69F0AE2AEBAEE9931D0B5A969F904
        r = 0xAD04DDE87B84747A243A631EA47A1BA6D1FAA059149AD2440DE6FBA6
        s = 0x178D49B1AE90E3D8B629BE3DB5683915F4E8C99FDF6E666CF37ADCFD

        self._run_224(message, H, k, (r, s))


    def test_vec18(self):
        message = b'test'
        H = SHA384()
        k = 0x7046742B839478C1B5BD31DB2E862AD868E1A45C863585B5F22BDC2D
        r = 0x389B92682E399B26518A95506B52C03BC9379A9DADF3391A21FB0EA4
        s = 0x414A718ED3249FF6DBC5B50C27F71F01F070944DA22AB1F78F559AAB

        self._run_224(message, H, k, (r, s))


    def test_vec19(self):
        message = b'test'
        H = SHA512()
        k = 0xE39C2AA4EA6BE2306C72126D40ED77BF9739BB4D6EF2BBB1DCB6169D
        r = 0x049F050477C5ADD858CAC56208394B5A55BAEBBE887FDF765047C17C
        s = 0x077EB13E7005929CEFA3CD0403C7CDCC077ADF4E44F3C41B2F60ECFF

        self._run_224(message, H, k, (r, s))


    def test_vec20(self):
        message = b'sample'
        H = SHA1()
        k = 0x882905F1227FD620FBF2ABF21244F0BA83D0DC3A9103DBBEE43A1FB858109DB4
        r = 0x61340C88C3AAEBEB4F6D667F672CA9759A6CCAA9FA8811313039EE4A35471D32
        s = 0x6D7F147DAC089441BB2E2FE8F7A3FA264B9C475098FDCF6E00D7C996E1B8B7EB

        self._run_256(message, H, k, (r, s))


    def test_vec21(self):
        message = b'sample'
        H = SHA224()
        k = 0x103F90EE9DC52E5E7FB5132B7033C63066D194321491862059967C715985D473
        r = 0x53B2FFF5D1752B2C689DF257C04C40A587FABABB3F6FC2702F1343AF7CA9AA3F
        s = 0xB9AFB64FDC03DC1A131C7D2386D11E349F070AA432A4ACC918BEA988BF75C74C

        self._run_256(message, H, k, (r, s))


    def test_vec22(self):
        message = b'sample'
        H = SHA256()
        k = 0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
        r = 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
        s = 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8

        self._run_256(message, H, k, (r, s))


    def test_vec23(self):
        message = b'sample'
        H = SHA384()
        k = 0x09F634B188CEFD98E7EC88B1AA9852D734D0BC272F7D2A47DECC6EBEB375AAD4
        r = 0x0EAFEA039B20E9B42309FB1D89E213057CBF973DC0CFC8F129EDDDC800EF7719
        s = 0x4861F0491E6998B9455193E34E7B0D284DDD7149A74B95B9261F13ABDE940954

        self._run_256(message, H, k, (r, s))


    def test_vec24(self):
        message = b'sample'
        H = SHA512()
        k = 0x5FA81C63109BADB88C1F367B47DA606DA28CAD69AA22C4FE6AD7DF73A7173AA5
        r = 0x8496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F00
        s = 0x2362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE

        self._run_256(message, H, k, (r, s))


    def test_vec25(self):
        message = b'test'
        H = SHA1()
        k = 0x8C9520267C55D6B980DF741E56B4ADEE114D84FBFA2E62137954164028632A2E
        r = 0x0CBCC86FD6ABD1D99E703E1EC50069EE5C0B4BA4B9AC60E409E8EC5910D81A89
        s = 0x01B9D7B73DFAA60D5651EC4591A0136F87653E0FD780C3B1BC872FFDEAE479B1

        self._run_256(message, H, k, (r, s))


    def test_vec26(self):
        message = b'test'
        H = SHA224()
        k = 0x669F4426F2688B8BE0DB3A6BD1989BDAEFFF84B649EEB84F3DD26080F667FAA7
        r = 0xC37EDB6F0AE79D47C3C27E962FA269BB4F441770357E114EE511F662EC34A692
        s = 0xC820053A05791E521FCAAD6042D40AEA1D6B1A540138558F47D0719800E18F2D

        self._run_256(message, H, k, (r, s))


    def test_vec27(self):
        message = b'test'
        H = SHA256()
        k = 0xD16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0
        r = 0xF1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367
        s = 0x019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083

        self._run_256(message, H, k, (r, s))


    def test_vec28(self):
        message = b'test'
        H = SHA384()
        k = 0x16AEFFA357260B04B1DD199693960740066C1A8F3E8EDD79070AA914D361B3B8
        r = 0x83910E8B48BB0C74244EBDF7F07A1C5413D61472BD941EF3920E623FBCCEBEB6
        s = 0x8DDBEC54CF8CD5874883841D712142A56A8D0F218F5003CB0296B6B509619F2C

        self._run_256(message, H, k, (r, s))


    def test_vec29(self):
        message = b'test'
        H = SHA512()
        k = 0x6915D11632ACA3C40D5D51C08DAF9C555933819548784480E93499000D9F0B7F
        r = 0x461D93F31B6540894788FD206C07CFA0CC35F46FA3C91816FFF1040AD1581A04
        s = 0x39AF9F15DE0DB8D97E72719C74820D304CE5226E32DEDAE67519E840D1194E55

        self._run_256(message, H, k, (r, s))



    def test_vec30(self):
        message = b'sample'
        H = SHA1()
        k = 0x089C071B419E1C2820962321787258469511958E80582E95D8378E0C2CCDB3CB42BEDE42F50E3FA3C71F5A76724281D31D9C89F0F91FC1BE4918DB1C03A5838D0F9
        r = 0x0343B6EC45728975EA5CBA6659BBB6062A5FF89EEA58BE3C80B619F322C87910FE092F7D45BB0F8EEE01ED3F20BABEC079D202AE677B243AB40B5431D497C55D75D
        s = 0x0E7B0E675A9B24413D448B8CC119D2BF7B2D2DF032741C096634D6D65D0DBE3D5694625FB9E8104D3B842C1B0E2D0B98BEA19341E8676AEF66AE4EBA3D5475D5D16

        self._run_521(message, H, k, (r, s))


    def test_vec31(self):
        message = b'sample'
        H = SHA224()
        k = 0x121415EC2CD7726330A61F7F3FA5DE14BE9436019C4DB8CB4041F3B54CF31BE0493EE3F427FB906393D895A19C9523F3A1D54BB8702BD4AA9C99DAB2597B92113F3
        r = 0x1776331CFCDF927D666E032E00CF776187BC9FDD8E69D0DABB4109FFE1B5E2A30715F4CC923A4A5E94D2503E9ACFED92857B7F31D7152E0F8C00C15FF3D87E2ED2E
        s = 0x050CB5265417FE2320BBB5A122B8E1A32BD699089851128E360E620A30C7E17BA41A666AF126CE100E5799B153B60528D5300D08489CA9178FB610A2006C254B41F

        self._run_521(message, H, k, (r, s))


    def test_vec32(self):
        message = b'sample'
        H = SHA256()
        k = 0x0EDF38AFCAAECAB4383358B34D67C9F2216C8382AAEA44A3DAD5FDC9C32575761793FEF24EB0FC276DFC4F6E3EC476752F043CF01415387470BCBD8678ED2C7E1A0
        r = 0x1511BB4D675114FE266FC4372B87682BAECC01D3CC62CF2303C92B3526012659D16876E25C7C1E57648F23B73564D67F61C6F14D527D54972810421E7D87589E1A7
        s = 0x04A171143A83163D6DF460AAF61522695F207A58B95C0644D87E52AA1A347916E4F7A72930B1BC06DBE22CE3F58264AFD23704CBB63B29B931F7DE6C9D949A7ECFC

        self._run_521(message, H, k, (r, s))


    def test_vec33(self):
        message = b'sample'
        H = SHA384()
        k = 0x1546A108BC23A15D6F21872F7DED661FA8431DDBD922D0DCDB77CC878C8553FFAD064C95A920A750AC9137E527390D2D92F153E66196966EA554D9ADFCB109C4211
        r = 0x1EA842A0E17D2DE4F92C15315C63DDF72685C18195C2BB95E572B9C5136CA4B4B576AD712A52BE9730627D16054BA40CC0B8D3FF035B12AE75168397F5D50C67451
        s = 0x1F21A3CEE066E1961025FB048BD5FE2B7924D0CD797BABE0A83B66F1E35EEAF5FDE143FA85DC394A7DEE766523393784484BDF3E00114A1C857CDE1AA203DB65D61

        self._run_521(message, H, k, (r, s))


    def test_vec34(self):
        message = b'sample'
        H = SHA512()
        k = 0x1DAE2EA071F8110DC26882D4D5EAE0621A3256FC8847FB9022E2B7D28E6F10198B1574FDD03A9053C08A1854A168AA5A57470EC97DD5CE090124EF52A2F7ECBFFD3
        r = 0x0C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F174E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E377FA
        s = 0x0617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF282623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A67A

        self._run_521(message, H, k, (r, s))


    def test_vec35(self):
        message = b'test'
        H = SHA1()
        k = 0x0BB9F2BF4FE1038CCF4DABD7139A56F6FD8BB1386561BD3C6A4FC818B20DF5DDBA80795A947107A1AB9D12DAA615B1ADE4F7A9DC05E8E6311150F47F5C57CE8B222
        r = 0x13BAD9F29ABE20DE37EBEB823C252CA0F63361284015A3BF430A46AAA80B87B0693F0694BD88AFE4E661FC33B094CD3B7963BED5A727ED8BD6A3A202ABE009D0367
        s = 0x1E9BB81FF7944CA409AD138DBBEE228E1AFCC0C890FC78EC8604639CB0DBDC90F717A99EAD9D272855D00162EE9527567DD6A92CBD629805C0445282BBC916797FF

        self._run_521(message, H, k, (r, s))


    def test_vec36(self):
        message = b'test'
        H = SHA224()
        k = 0x040D09FCF3C8A5F62CF4FB223CBBB2B9937F6B0577C27020A99602C25A01136987E452988781484EDBBCF1C47E554E7FC901BC3085E5206D9F619CFF07E73D6F706
        r = 0x1C7ED902E123E6815546065A2C4AF977B22AA8EADDB68B2C1110E7EA44D42086BFE4A34B67DDC0E17E96536E358219B23A706C6A6E16BA77B65E1C595D43CAE17FB
        s = 0x177336676304FCB343CE028B38E7B4FBA76C1C1B277DA18CAD2A8478B2A9A9F5BEC0F3BA04F35DB3E4263569EC6AADE8C92746E4C82F8299AE1B8F1739F8FD519A4

        self._run_521(message, H, k, (r, s))


    def test_vec37(self):
        message = b'test'
        H = SHA256()
        k = 0x01DE74955EFAABC4C4F17F8E84D881D1310B5392D7700275F82F145C61E843841AF09035BF7A6210F5A431A6A9E81C9323354A9E69135D44EBD2FCAA7731B909258
        r = 0x00E871C4A14F993C6C7369501900C4BC1E9C7B0B4BA44E04868B30B41D8071042EB28C4C250411D0CE08CD197E4188EA4876F279F90B3D8D74A3C76E6F1E4656AA8
        s = 0x0CD52DBAA33B063C3A6CD8058A1FB0A46A4754B034FCC644766CA14DA8CA5CA9FDE00E88C1AD60CCBA759025299079D7A427EC3CC5B619BFBC828E7769BCD694E86

        self._run_521(message, H, k, (r, s))


    def test_vec38(self):
        message = b'test'
        H = SHA384()
        k = 0x1F1FC4A349A7DA9A9E116BFDD055DC08E78252FF8E23AC276AC88B1770AE0B5DCEB1ED14A4916B769A523CE1E90BA22846AF11DF8B300C38818F713DADD85DE0C88
        r = 0x14BEE21A18B6D8B3C93FAB08D43E739707953244FDBE924FA926D76669E7AC8C89DF62ED8975C2D8397A65A49DCC09F6B0AC62272741924D479354D74FF6075578C
        s = 0x133330865C067A0EAF72362A65E2D7BC4E461E8C8995C3B6226A21BD1AA78F0ED94FE536A0DCA35534F0CD1510C41525D163FE9D74D134881E35141ED5E8E95B979

        self._run_521(message, H, k, (r, s))


    def test_vec39(self):
        message = b'test'
        H = SHA512()
        k = 0x16200813020EC986863BEDFC1B121F605C1215645018AEA1A7B215A564DE9EB1B38A67AA1128B80CE391C4FB71187654AAA3431027BFC7F395766CA988C964DC56D
        r = 0x13E99020ABF5CEE7525D16B69B229652AB6BDF2AFFCAEF38773B4B7D08725F10CDB93482FDCC54EDCEE91ECA4166B2A7C6265EF0CE2BD7051B7CEF945BABD47EE6D
        s = 0x1FBD0013C674AA79CB39849527916CE301C66EA7CE8B80682786AD60F98F7E78A19CA69EFF5C57400E3B3A0AD66CE0978214D13BAF4E9AC60752F7B155E2DE4DCE3

        self._run_521(message, H, k, (r, s))
