from samson.encoding.general import PKIAutoParser, PKIEncoding

# These have to be here so the auto parser works
from samson.protocols.diffie_hellman import DiffieHellman # noqa: F401
from samson.public_key.rsa import RSA # noqa: F401
from samson.public_key.ecdsa import ECDSA # noqa: F401
from samson.public_key.eddsa import EdDSA # noqa: F401
import unittest

# DH
# ------
# dnssec-keygen -a DH -b 512 -n USER dh
DH_PUB_1 = b'dh. IN KEY 0 3 2 AECHunhq3ZeedSmVs+oWPKdjJmqvSLj3pRXazTDpr0mYqvVl83KiQeqR hzenJ4Xi1/4gaZn3eZk6N3ygvq5LBtI7AAECAEBzFgiRXpmg5s7MNwZu 79s7lZJbTAuADT1pkFTj9M+dPQolJy+omxS6lOZd9oEy7CqNixzQvB5h V00Qajz2qw/b'

DH_PRIV_1 = b'''Private-key-format: v1.3
Algorithm: 2 (DH)
Prime(p): h7p4at2XnnUplbPqFjynYyZqr0i496UV2s0w6a9JmKr1ZfNyokHqkYc3pyeF4tf+IGmZ93mZOjd8oL6uSwbSOw==
Generator(g): Ag==
Private_value(x): ZrtK4NMSVlhYwYynM16tB3PByOaj5QZHO8P06AyQ9Qk/7KxJctwERshAB5uMhI98BpaQudhnQ3R5bjE6dQQofA==
Public_value(y): cxYIkV6ZoObOzDcGbu/bO5WSW0wLgA09aZBU4/TPnT0KJScvqJsUupTmXfaBMuwqjYsc0LweYVdNEGo89qsP2w==
Created: 20200827134343
Publish: 20200827134343
Activate: 20200827134343'''


# dnssec-keygen -a DH -b 1024 -n USER dh_1024
DH_PUB_2 = b'dh_1024. IN KEY 0 3 2 AAECAAAAgGJRHThydumr9R2gt5tfuLjiTEiy4kwbmaKIX9ujBltS9BIR R8qIMYJp893GQYLCduaHxrXqv0fO5ga6s24/9e2iuPbP2piaFCCiK+l9 F4mAiOCnBL1ALfb3xnHH6ylgd7XxIhPMM3xS0uhCSqpMIQV8PfCh64Ei zMCEaEozxPHA'

DH_PRIV_2 = b'''Private-key-format: v1.3
Algorithm: 2 (DH)
Prime(p): ///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxObIlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjftawv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5lOB//////////8=
Generator(g): Ag==
Private_value(x): WS0ReUUR5C5XbQnMIW1e2blj9IqQTV3ib4RkWiokAF6XzS6pjJ+5mr50m9OKy5JBHnLeQXQKtZLIfn0FnvynBNiL4MKoEuXy63zyQuT2vyWJvXKBeBlpMkbw5qaFSf9np0Nz6yEXvYfo+eoNbXfa2E43/lyet8NaICZEWNIcDy8=
Public_value(y): YlEdOHJ26av1HaC3m1+4uOJMSLLiTBuZoohf26MGW1L0EhFHyogxgmnz3cZBgsJ25ofGteq/R87mBrqzbj/17aK49s/amJoUIKIr6X0XiYCI4KcEvUAt9vfGccfrKWB3tfEiE8wzfFLS6EJKqkwhBXw98KHrgSLMwIRoSjPE8cA=
Created: 20200827153441
Publish: 20200827153441
Activate: 20200827153441'''



# from samson.encoding.dns_key.dns_key_rsa_private_key import DNSKeyRSAPrivateKey
# rsa = DNSKeyRSAPrivateKey.decode(key)
# DNSKeyRSAPrivateKey.encode(rsa).split(b'\n')[:-3] == key.split(b'\n')[:-3]


# RSA
# --------
# dnssec-keygen -a RSASHA256 -b 1024 rsa_1024
RSA_PUB_1 = b'rsa_1024. IN DNSKEY 256 3 8 AwEAAcHXifAHKku3UbamEOCXlmhg7TcBLcOvyR5fglFs6d9N0iKsMYh0 DX8mZAGBwgvMCYlQFdXHVWbtMGBq25EhsC7lnEcKrs3oGG6/PGzTnqET qSofOyQAkBU0YVbBO58lLX/BiPyieAmXw0g3Hwej0THxRatS3AYnGFqf 6l3oTq5V'

RSA_PRIV_1 = b'''Private-key-format: v1.3
Algorithm: 8 (RSASHA256)
Modulus: wdeJ8AcqS7dRtqYQ4JeWaGDtNwEtw6/JHl+CUWzp303SIqwxiHQNfyZkAYHCC8wJiVAV1cdVZu0wYGrbkSGwLuWcRwquzegYbr88bNOeoROpKh87JACQFTRhVsE7nyUtf8GI/KJ4CZfDSDcfB6PRMfFFq1LcBicYWp/qXehOrlU=
PublicExponent: AQAB
PrivateExponent: reIQbY2v5k3i8ipT93RjyuwvvujCyciVbDaW6z39KYBgoRPANzyLouSoTyW8EOMOJuv9OlDejj7053jTz4PdyxMih3ezDPN8Kv3sG4Rsp50QzEQYnVPNhDG4ZEywZjYMlRPhZp5sKF5slh3sahAlRZ37a+AU7fLoFDSDtYHza50=
Prime1: 710gZicWO/suJgYdBmwQHwK0AyLBlh5o/chEkQ5PUO3TTytitnNJIhVaIkbOC6M46FE8o4d9rLH9/qBLTrmXbw==
Prime2: z1B3ZZ4cMMi04LfHi5CdoylhMOAuxNmC73a1i26xCuhziPfR7lcr4BZpLriweK1hIkbBgILIYKoPxzsgsnXUew==
Exponent1: kokngYIiSXwfJ2YMtNbJE8L64wSPENDzI5JL76WcBwZhm5EK8HkpZ3U85ckE8PjuqMK65b3XwTaCMTR+heZ2fw==
Exponent2: PKdIJ1zY1pUCBnT+VqDa3e+vVcNhK4qPuku61a5u8cgMdVg7/UVXutoTr+2tA8GGF6cn2ddplI5sy1dLO6spnQ==
Coefficient: fNXBmdD6TnOHNTav2oaJeITxuStgSW5eyEdkeNQzYfZ/79p6NVfXF6ccZuFEz0YLGyS3jYpvBMD8DnxZRWv/8g==
Created: 20200827214917
Publish: 20200827214917
Activate: 20200827214917'''


# dnssec-keygen -a NSEC3RSASHA1 -b 2048 rsa_2048
RSA_PUB_2 = b'rsa_2048. IN DNSKEY 256 3 7 AwEAAct9rKDkp2ilaTbW4YsPURl5RnytVIrZ3aU1RQI8XR7gEphjh6u1 VVGwrc6ykk/V9LDkT1EDUrf16zHI4D8wVjTZLP7rv/oVYBHkvdl6Mj6p yrAV0ZljONHUeQfK6/ST/DuELkvEPLDmxuA4qr6TO47ke0xnvl+R3KjH NDsLTgfgIv/CxpEamvFsc6UWiuUU5MbnglgJ61dKO0WfrCu0hAKMCezX NtwP919IcNgN7WEIXVM9/TisXIEeIldemRgjR0aMpHC1+CRF6CBvPbfR tBlsn8ta0GS0Bu6RFPDXLYAjnAvbV1OZ1FH5Az2+saMQa5I9bwWNdnXp cHEJRW07pfU='

RSA_PRIV_2 = b'''Private-key-format: v1.3
Algorithm: 7 (NSEC3RSASHA1)
Modulus: y32soOSnaKVpNtbhiw9RGXlGfK1UitndpTVFAjxdHuASmGOHq7VVUbCtzrKST9X0sORPUQNSt/XrMcjgPzBWNNks/uu/+hVgEeS92XoyPqnKsBXRmWM40dR5B8rr9JP8O4QuS8Q8sObG4DiqvpM7juR7TGe+X5HcqMc0OwtOB+Ai/8LGkRqa8WxzpRaK5RTkxueCWAnrV0o7RZ+sK7SEAowJ7Nc23A/3X0hw2A3tYQhdUz39OKxcgR4iV16ZGCNHRoykcLX4JEXoIG89t9G0GWyfy1rQZLQG7pEU8NctgCOcC9tXU5nUUfkDPb6xoxBrkj1vBY12delwcQlFbTul9Q==
PublicExponent: AQAB
PrivateExponent: MlNSbjgebvL5omZiQVH4bKRhmlQDpJNdDY6vEm57WTdxYd67nuupvhpD4eqn5La1XUoZk5+OxZA8KoPTcc0yhL9xMVp8kAzZRZOcoDxoULcNOZ8rxxOS6dHyXMsCr+opZ065ZGOT3uw0Ix/gmmEvSZeYJr1Bh8E7IUKi2DdjhO6o037GaBJL0o09TVLzZ1m8QG08bKO3bVaFPlm9T5xvbnqIB80yoeyJYM4lQ82UzzziIIIHAzTLp9vtMdB1C0Ka3neksrcok7+tTMGsusdBHirZ63DKA7dUfw8k0Eh6rwwABRw6tsENFXDfk9T6xR/bItTKRqg/zFbDRaKEsfOqAQ==
Prime1: 5e2uOj7cfZVJwbFJBdw0AMGxVc4g58Ryhkz+THT9nz3CeyTE/+wu8R0qP4g8TOlERzNpmt7EQKVyHNCC1y6DaaVFjxB4SEr/8PKzXIAgletGXSbQNZ/ipGimV6kkIV+HTorYizECFDMTEzOfmK+ZMUOWACy7cd0OT+VUNWX2hR0=
Prime2: 4pCR/a6ZSH9fWVXaJNcjjO0NyhOjM1HtZkzM6MpFsUuUYoUE6Jv9p8jy4e24eNeEoitjjfz5T7eqrZ4lMGqkEKlTKe9XynbWP8OcI/2BKrr5p6EWRQcCB3HlHlTiIb3yPZC9DQkirtVj9okqPS6vlDsyOBRr0bqduT4IS5k1BLk=
Exponent1: SJPpDiuvj9ii6ogao8XpiF+bqZkiW+ZvvCLrlpjLQgvNqu9lW99ixetN3bYUSrbLPapl6GPvEPToe136HxBonN11gn5RaYh7F8SUh1tObeRRVrAcwwCQGxOJhlw2sm4kGM/NIMq8fEHPAJ2oABtVwO4zmCSGmp+Ll/6swRpJYaU=
Exponent2: w1OqWZAOnJ8bYBSRFlPYVWYGDmKxv8vxJNIvkr7YKMslKW7O1Y+uttma9EcTVDNSKNHJaZ9gfWa2IiqGm2BFBAxHI48yG94qRhzpX2nt0x4RoIBTh71L9Yku4+CAeGCfGI7RPgzTNvHH1cNZhBfczanfWNPaRJ1j31Foq2xxdhk=
Coefficient: 5F6wnFp/cdkSW1x0akr/fRdUvb4Ynr9yH7VzDo9Zr4d4oi1+HrKXmZQsN3mN4SduEdwEFpZV4OsKLPmU52w8qyPCT69iMWQNI+7oY15WF2E2/T1WyoNlZAosJ/9Zdp4utzZjb8JKDoElL2edFCNQbFedGgh0OUq/CJkRekbkSzM=
Created: 20200827215016
Publish: 20200827215016
Activate: 20200827215016'''



# ECDSA
# -------
# dnssec-keygen -a ECDSAP256SHA256 ecdsa256
ECDSA_PUB_1 = b'ecdsa256. IN DNSKEY 256 3 13 y4JUcZVjZY0wLeUV8RwFHb1OI0acv4tPNNcntXe3B3bD+kLobgVF/oZK oLttnDqyWOE1ZlTqB9SKBdyg8ZBn8w=='

ECDSA_PRIV_1 = b'''Private-key-format: v1.3
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: fn44IocFUnHopqQ5UIaitEHxs4LghM1UWpKU+6BAKZo=
Created: 20200827215112
Publish: 20200827215112
Activate: 20200827215112'''


# dnssec-keygen -a ECDSAP384SHA384 ecdsa384
ECDSA_PUB_2 = b'ecdsa384. IN DNSKEY 256 3 14 qqAv/2RIYSErrh24kI89oJ3kSpd2Lvv+5EaNSyWKfoG1HBxm1J/uS37l aWSXIDR7NF6dnuvUgliKbTuYmTTgl1Qr/Ja79S4ysV18C++gPsp13jdK DqLj631w9JJSoLxy'

ECDSA_PRIV_2 = b'''Private-key-format: v1.3
Algorithm: 14 (ECDSAP384SHA384)
PrivateKey: BmHbNqYazyOyP8uuqpmyz1YPLDuVlQvc8QxsjYT9l/2CxpNUq2IdPQDpIFOd6KJP
Created: 20200827215200
Publish: 20200827215200
Activate: 20200827215200'''


# EdDSA
# -------
# dnssec-keygen -a ED25519 ed25519
ED_PUB_1 = b'ed25519. IN DNSKEY 256 3 15 CL8hhiera/2YDI6+T/tpCXsqjeyZ7HK9/re+sBTiDnE='

ED_PRIV_1 = b'''Private-key-format: v1.3
Algorithm: 15 (ED25519)
PrivateKey: xWD+Iw15xIP5vucvp71krA/73+T9QkVOPI9uAtoVh1k=
Created: 20200827215339
Publish: 20200827215339
Activate: 20200827215339'''


# dnssec-keygen -a ED448 ed448
ED_PUB_2 = b'ed448. IN DNSKEY 256 3 16 9jvX8u/IfXwb4omqc/7jBxXNUbkw1Mf1n72xQYHJQIp44v0FgkxsMuzs mXpzC8EvdH6Junggl7SA'

ED_PRIV_2 = b'''Private-key-format: v1.3
Algorithm: 16 (ED448)
PrivateKey: sqscyfAOPcoXRzoC3ON4r+G0dEbFgcJf0bX+dJ9b3dmlao+azIurqGP/P+bVA2vT5/cwBQnubHdN
Created: 20200827215419
Publish: 20200827215419
Activate: 20200827215419'''


PAIRS = [(DH_PUB_1, DH_PRIV_1), (DH_PUB_2, DH_PRIV_2), (RSA_PUB_1, RSA_PRIV_1), (RSA_PUB_2, RSA_PRIV_2), (ECDSA_PUB_1, ECDSA_PRIV_1), (ECDSA_PUB_2, ECDSA_PRIV_2), (ED_PUB_1, ED_PRIV_1), (ED_PUB_2, ED_PRIV_2)]


class DNSKeyTestCase(unittest.TestCase):
    def test_keys(self):
        for pub_bytes, priv_bytes in PAIRS:
            pub  = PKIAutoParser.import_key(pub_bytes).key
            assert b''.join(pub.export_public_key(encoding=PKIEncoding.DNS_KEY).encode().split(b' ')[3:]) == b''.join(pub_bytes.split(b' ')[6:])

            priv = PKIAutoParser.import_key(priv_bytes).key
            assert priv.export_private_key(encoding=PKIEncoding.DNS_KEY).encode().split(b'\n')[2:-3] == priv_bytes.split(b'\n')[2:-3]
