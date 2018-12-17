from samson.public_key.dsa import DSA
from samson.utilities.bytes import Bytes
from samson.utilities.pem import RFC1423_ALGOS
import hashlib
import unittest


# openssl dsaparam -out dsaparam.pem 2048
# openssl gendsa -out test_dsa.pem dsaparam.pem
# openssl dsa -in test_dsa.pem -text
# openssl dsa -in test_dsa.pem -pubout -text
# openssl dsa -pubin -in test_dsa.pub -pubout -text


TEST_PRIV = b"""-----BEGIN DSA PRIVATE KEY-----
MIIDVgIBAAKCAQEAr9QOzmLmfkEjvB4xt3dBnyGLSKrLpp1WAVkZeElygI+CkbR8
h4fTuaUHuCFX70w/q7egnu5TwG/DZGPcThg6FKe8i6mRDwnD5y6s/Lu3Niojhrrv
CUxs3yJJYvyjrPwKdtMkeVkoiTZeFEeWBXhrgxF6rEWkJBKloZNG32NXqW9gcpfy
ecJ4v0yffuZWjftU0nO+3Yo1VQsGiY0fA8mFfYXNGXCbLENF8jclW7QpuKdcHXkB
deKofZRj+6nV/duLTWL6hOPqqEBc34B4ApeGfFAissN5Juf0Nzku3KIkp23hHZtW
pH0cHz4JpASDg3Y3grhcDy0mjuWt9iyYo2YuIwIhAJD4vs9Y2Oo+I7PRFFouK6Wz
CtO44JKlADo4c4poFGFbAoIBAFgxG8YaNzWyFf1sJuMbBZ1Pq6SOfZ+7A8bH1QRw
0d3DnT8fIkDy4uwmYKtq2lDxyGd+HyJcvzVVttuphfgMo6DevT8DpicKAmGA7y//
0NPCAt1eHx5aYIELxZGfhjdManb6N8hhUmhzzJ1JqqrKj4P60/JZwzYlIfntkIpP
gsXKuAOW3Wf/3s55dnguNwrRHD525xi9qisBXaUBKLViKmEH0lVjEN+RmB2fEjt1
C6xJx4CKQd7hZrBneXz8zLpZc5pCaEStcYpc411IZXQTl3SwMiA7IdlYTN1okXQB
oPal453z1cov8exg3erfs2OkWBH/JLMFssICuGPAVJ7CesACggEBAIU5+UpNOO6r
fvNzveNGnirqEzYTa2w0uEWEun4d/t0jhxDI34vSO6zA5oFwaZ4BFsuxTVzVAKF5
oSaKw2G3qsQ4QLr89VO/QHkbnrRLvkCa1cPZbY4eqPGzMlQsLTrBCb1zwH8Gbpx+
gcSVAwEyOdotoS8VWtURJNI/JaiTQN5ueZtrtKc4rJRg/oHvxgDrDEaqAuAakbr2
03+ZLCimsXVGDpVYoUu+i1su7P9ksLuVJE08ugcmVmZTSJURnao54AzOiVxQE3dH
hg6B3Jd661aatPJNRXyYBFTR5XHH8wclAjxbdMTqru/d8Ig6zAzNZulCbbBydawh
tZSAKpT1c+QCIGfUX0ksNEYbIsoy+Xt1caTltO3zbXuiMOA6bR4E/j8J
-----END DSA PRIVATE KEY-----"""

TEST_PUB = b"""-----BEGIN PUBLIC KEY-----
MIIDRzCCAjkGByqGSM44BAEwggIsAoIBAQCv1A7OYuZ+QSO8HjG3d0GfIYtIqsum
nVYBWRl4SXKAj4KRtHyHh9O5pQe4IVfvTD+rt6Ce7lPAb8NkY9xOGDoUp7yLqZEP
CcPnLqz8u7c2KiOGuu8JTGzfIkli/KOs/Ap20yR5WSiJNl4UR5YFeGuDEXqsRaQk
EqWhk0bfY1epb2Byl/J5wni/TJ9+5laN+1TSc77dijVVCwaJjR8DyYV9hc0ZcJss
Q0XyNyVbtCm4p1wdeQF14qh9lGP7qdX924tNYvqE4+qoQFzfgHgCl4Z8UCKyw3km
5/Q3OS7coiSnbeEdm1akfRwfPgmkBIODdjeCuFwPLSaO5a32LJijZi4jAiEAkPi+
z1jY6j4js9EUWi4rpbMK07jgkqUAOjhzimgUYVsCggEAWDEbxho3NbIV/Wwm4xsF
nU+rpI59n7sDxsfVBHDR3cOdPx8iQPLi7CZgq2raUPHIZ34fIly/NVW226mF+Ayj
oN69PwOmJwoCYYDvL//Q08IC3V4fHlpggQvFkZ+GN0xqdvo3yGFSaHPMnUmqqsqP
g/rT8lnDNiUh+e2Qik+Cxcq4A5bdZ//eznl2eC43CtEcPnbnGL2qKwFdpQEotWIq
YQfSVWMQ35GYHZ8SO3ULrEnHgIpB3uFmsGd5fPzMullzmkJoRK1xilzjXUhldBOX
dLAyIDsh2VhM3WiRdAGg9qXjnfPVyi/x7GDd6t+zY6RYEf8kswWywgK4Y8BUnsJ6
wAOCAQYAAoIBAQCFOflKTTjuq37zc73jRp4q6hM2E2tsNLhFhLp+Hf7dI4cQyN+L
0juswOaBcGmeARbLsU1c1QCheaEmisNht6rEOEC6/PVTv0B5G560S75AmtXD2W2O
HqjxszJULC06wQm9c8B/Bm6cfoHElQMBMjnaLaEvFVrVESTSPyWok0Debnmba7Sn
OKyUYP6B78YA6wxGqgLgGpG69tN/mSwoprF1Rg6VWKFLvotbLuz/ZLC7lSRNPLoH
JlZmU0iVEZ2qOeAMzolcUBN3R4YOgdyXeutWmrTyTUV8mARU0eVxx/MHJQI8W3TE
6q7v3fCIOswMzWbpQm2wcnWsIbWUgCqU9XPk
-----END PUBLIC KEY-----"""


# ssh-keygen -t dsa -f test_dsa_ssh
# ssh-keygen -e -f test_dsa_ssh
TEST_SSH_PRIV = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABsQAAAAdzc2gtZH
NzAAAAgQCyDpXjyCzOzkg/goozbmbeMyeLq+fbI5Wih6hQ5Y3KNHC5D0XQXkIAIcK8kgtU
qxP0aczjPsNn5ug8E8xA9VVzlCe5CoazZUhzGNy4Sd711PzzfIZwtAfafRwhkeDqQQPvJA
SDaTSUW/D2rDWcY6MoV/Ib+aQrYPXI6zziEw+5EwAAABUAsTJsICjVdb9E1qNxD5n0oWiB
baUAAACAAd3qkYA/F2X5rGQOqhD3qXESNCw8mHx36hPrGk0Hg4kPAarpseCUvQAD6ZWeGp
TKWuv78goAF8lLhZTa97w85QZ8Vh4sMPunPhKt6y/jireH7lXzk+sYxLnX6GmLHbyityPO
oV6e7mdVwisQMTN4lgLo1kUF/2jnliA6dTWZKGUAAACAJqYEump51X9nOoD/X/2266ViY2
kwzDb51TNK+H0Xx/EDDo1NbIWsnw99fOnXjJWGXzAt4zxEXY5P/bZfM/9OXJ5CV8D3E8Lp
uaQW7ySicRDpdWZIP6+2NkY4HJhj0pn33rur1tsriLr0NyjBGpXFPksM/XEdux1vOBrpcR
6pbMgAAAHoxd+XqsXfl6oAAAAHc3NoLWRzcwAAAIEAsg6V48gszs5IP4KKM25m3jMni6vn
2yOVooeoUOWNyjRwuQ9F0F5CACHCvJILVKsT9GnM4z7DZ+boPBPMQPVVc5QnuQqGs2VIcx
jcuEne9dT883yGcLQH2n0cIZHg6kED7yQEg2k0lFvw9qw1nGOjKFfyG/mkK2D1yOs84hMP
uRMAAAAVALEybCAo1XW/RNajcQ+Z9KFogW2lAAAAgAHd6pGAPxdl+axkDqoQ96lxEjQsPJ
h8d+oT6xpNB4OJDwGq6bHglL0AA+mVnhqUylrr+/IKABfJS4WU2ve8POUGfFYeLDD7pz4S
resv44q3h+5V85PrGMS51+hpix28orcjzqFenu5nVcIrEDEzeJYC6NZFBf9o55YgOnU1mS
hlAAAAgCamBLpqedV/ZzqA/1/9tuulYmNpMMw2+dUzSvh9F8fxAw6NTWyFrJ8PfXzp14yV
hl8wLeM8RF2OT/22XzP/TlyeQlfA9xPC6bmkFu8konEQ6XVmSD+vtjZGOByYY9KZ9967q9
bbK4i69DcowRqVxT5LDP1xHbsdbzga6XEeqWzIAAAAFEcWAvQWXa3f8yu1ehaK9Vnb+EqT
AAAAEWRvbmFsZEBEb25hbGQtTUJQAQI=
-----END OPENSSH PRIVATE KEY-----"""


TEST_SSH_PUB = b"ssh-dss AAAAB3NzaC1kc3MAAACBALIOlePILM7OSD+CijNuZt4zJ4ur59sjlaKHqFDljco0cLkPRdBeQgAhwrySC1SrE/RpzOM+w2fm6DwTzED1VXOUJ7kKhrNlSHMY3LhJ3vXU/PN8hnC0B9p9HCGR4OpBA+8kBINpNJRb8PasNZxjoyhX8hv5pCtg9cjrPOITD7kTAAAAFQCxMmwgKNV1v0TWo3EPmfShaIFtpQAAAIAB3eqRgD8XZfmsZA6qEPepcRI0LDyYfHfqE+saTQeDiQ8Bqumx4JS9AAPplZ4alMpa6/vyCgAXyUuFlNr3vDzlBnxWHiww+6c+Eq3rL+OKt4fuVfOT6xjEudfoaYsdvKK3I86hXp7uZ1XCKxAxM3iWAujWRQX/aOeWIDp1NZkoZQAAAIAmpgS6annVf2c6gP9f/bbrpWJjaTDMNvnVM0r4fRfH8QMOjU1shayfD3186deMlYZfMC3jPERdjk/9tl8z/05cnkJXwPcTwum5pBbvJKJxEOl1Zkg/r7Y2RjgcmGPSmffeu6vW2yuIuvQ3KMEalcU+Swz9cR27HW84GulxHqlsyA== nohost@localhost"

TEST_SSH2_PUB = b"""---- BEGIN SSH2 PUBLIC KEY ----
Comment: "1024-bit DSA, converted by nohost@localhost from OpenSSH"
AAAAB3NzaC1kc3MAAACBAIAAAAAAAAAAieGFUhig59rDgTb/r6cu2nhZ8hceJeZerGmMFw
JXiwfcKhB22iQcdsYtN02Diepa7/0yJqBTDMVl879rUJKROevqwE9Iw8hK+3ltYeWk+aj9
qBKrWUlCMsfStN61CqGO6eEyv6haxDdNf5CRq8PQFe/IcaWERxuxAAAAFQD09H8FeUslYX
S7pumzlqdwflY8WwAAAIBZWMnTiYsiSxJnLAuY4Gxg35I8uLyZnRGUWP71OLj6QEbI21MD
nbYgwJTJ+gd+84m1MipVmUanGQP5kPH34OAl4tf3z0lK/xoEcPW2TDa2JaCX8WUf53UyNV
b+ALNgjIh4koeEgOmQQb5gGmIWbKaJS91BpwVOyJ91a6n8lTAikQAAAIB/LGGoOyuL/zra
hx7LuyMWF/ruvSxiky4FPA2KorGG0xjY32k1GPQTw5818Itybr4CLB2jsw8oo6SHPVdSvZ
SWmPi/r70ltxQCIDstoJqaGE/0xD5S8W4T9IO3kbNr9boPEdQ8paf+CNZfVU4CTYgxjCQe
vlSTJVvZVKoQFKC4Lw==
---- END SSH2 PUBLIC KEY ----"""

# Generated using ssh-keygen and OpenSSL
# ssh-keygen -t dsa -N 'super secret passphrase' -f test_dsa_key -m PEM
# openssl dsa -aes192 -in test_dsa_key -text
# openssl dsa -aes256 -in test_dsa_key -text
# openssl dsa -des -in test_dsa_key -text
# openssl dsa -des3 -in test_dsa_key -text

PEM_PASSPHRASE = b"super secret passphrase"

TEST_PEM_DEC = b"""-----BEGIN DSA PRIVATE KEY-----
MIIBugIBAAKBgQDHngE0HhdDu3LTU/405rxhvVh8dl397TVeuc8WC8DEnzDXx+OY
RQSXDcQuU8vzAeCLaDjsHhS7wFWcfrWH0vlOyZXFLYsM5Qz+3oalxL9rrUspBYIi
3Yc73zGgRoNlHWsmCP3VuxFePZAG6mt/mYnzTxcnIoBnT6vuZAd4/Y5z9QIVAIYt
zW+l0wkMoIUPlOW/EJ0j3ivBAoGABRgyc5mbtlcqRc47R36CcV+6BvX0p9hH8Kwn
E6nxxPlOrTJ+h/xDLzYRnO5V2WfI52KtRahjEMl4yh5CJu+qq9VC2K6FMxMTSakH
bUxPJXj80i10L5WygbSXy0ZhuMR48+x71QFBtadeS/T+S5Jr5yJMU67nWCyxxH87
QWFdvFUCgYBoJToQycvDq0/yRqJYkn/dghmIIL/aHTlgDcZ99ShVuLI93JLsdeB0
d8ndksVuPp8ihvOixVir0xSeJU2yrw1RCIKL06Wt0abYtcCgGC4wAppOifSMk0Xf
LJNps8iFIAVmxHYEbUj9hYx3z+3+svNjfA5N+G4nYgi++WHNB2JuwAIUYHrNRMMT
loOdXmS1PY65gIgki24=
-----END DSA PRIVATE KEY-----"""


TEST_PEM_AES_128_ENC = b"""-----BEGIN DSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2B9284EDD25B215F7747517707E8326D

UndDJGFb/JFwLRubS1bQ4UdwxVy9SkzVwLsFjaqMC1jIbvpQQR56aGCVX7ZU6HHe
+y6gIN7R9llhWb8Jm/sSu0zWEc7L5x5Qj6qEVFH9usJ57IHr3SITgBrKD4d/AtrG
SyOHn8wusq2WKh//aF7WWgrcVv39Ew1Y4Br+KfB9O8TlZhf6fIDRGI/vOluccM/F
26jPzFGXMof/AFynrOQcqHVtCmdes1JtIxvfLYIVbGi+mC0Hvfd8JgQjYMmlxXyK
ZFrZbubjKpNTjnUo77JJ5EzP9fnciIA9/RvHTalL5Ox6bM5hjAUX9ohYc4cL2B10
kA9D6KprzCfecEyhQXOffR8od88DlpSrmMhXwbbWR+68Fsz6AUxOd9MGnckWiGYz
xa2BGE3EzC4R/FygcM4+c5mDlbebMPCRayD3CgdqBWVzB9HJK45uUDz9nQee74yy
Yzrna7I2KrnuirXoGBxiwnNL7b6StCGI4NSbU1evDZ0aKpR7mVQtvekFm+rBHaAd
qaXwrAQccSXjJFzFzcVEhsHEqaYJdOZckGiUcSzC5szGYBsF9BYBn0DF/OKK3t+b
YXoS3wf1KTGoNu4V1e3rPw==
-----END DSA PRIVATE KEY-----"""


TEST_PEM_AES_192_ENC = b"""-----BEGIN DSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-192-CBC,FAE20370CDB461ECA9ACEB9BBABF71E0

Yn3Zk2t5VD4ZciOlapMK+GioEg7Jf8Ckw+wC2F4RWmKOGJqNRtjrVqAtyxPR+hWM
xBax4KqW3LD5wWHUUL6lsQEs9LOzZ0PoIyZqXvSGkVZGMwhY0aRaFwdbb5j0pa+T
KMEmlkeISE+0Ti0OowoAknisiIYn3gk6OdaFJsLphxb0J99Ra119VNlh+penG2NY
4s6m6DlhckCSYm2xwBqJIQNXIYSY9PApGkFQhBrneWfOfynBF++vBNvxw+0anhgj
Dllxe3+KhwDecYvBH9ohL728eoL+NZSYkVaSYaRh9PIz82h8nRMcauiu6URBF6Ct
W+ceAscBz+CU2m6St04L6Mh1XQnlAV9kGQN2l4puKNIq7sWl8ldiA22l0l4DGiAj
cTF0KQoVMtxZv1FM1Psp6UBd2WO1bytuyq5TbketXHvLX28r6VHHl6fnrtmwnBTm
/FIkcwhKuDGOZzgdated+TQY+jxGvVDQJuQyWZ+eiO/478cSca8p4ynfkp/NC6/4
Uh3wR/MVE9XiJrMs8LlPbi0hxGqYuNZwN4uE37qc85pl/iDbDKwroY+S7jYZf6Jq
3LS+g7Obf/MBdw1zuglzag==
-----END DSA PRIVATE KEY-----"""


TEST_PEM_AES_256_ENC = b"""-----BEGIN DSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,DB3428E8CA39E58CD9EF75BE23557C23

lY/WwGbFxE5ZEZx1ZOqEGuOW6N/iTSgMC3zXxMCdyEfIDBLKw5Qbcez/OszZXgof
FcbHoY3KI6CSDLuNdLh64oQC6BqYrdsWgtUMDeUushASYrICeYJSq0dDywBFgpO+
p8UUVvUE0T5nMgaUMUNNkUB1qqbSgtoWa2ZaF7nON04tL+byLt1SK0rBw6zG3DtB
CNYofQmwpwbJQbCaxa90uq90NVG1EDupsK10eeS/TEtcGnIY28qU7z3BVyR9Hbsc
Noccf8qIqZXzT3i0c2wF4B+/OAYn177L+ZxLFKym7WsZP1fnYGSyRT91asR8Up2q
OkDgvMQoMa5GEcEdgx5Pw7WGBHPWyXd0e77SGgJbiGZfMivdVY4t9HVZnaW8KXK1
l5pLFpAh3ysrnNyNorGJlrCP9dE8W/1O2jrME9JyJtRPirZfA5vNQIx29sF4IQAc
8GPxK5C86yCtDKiXIp2fy16UybWOt7O0y6cRhyKs0p6Dg4Gv8RxQVqqOSKi2as28
ZVZpw2dLFVcX5Hp+EfAX9N9STUsfjBFck77SU/vA2eZhJS/vHI4IyoDuRix0x5eA
52/8RRDnrubWfP49kmNxkw==
-----END DSA PRIVATE KEY-----"""


TEST_PEM_DES_ENC = b"""-----BEGIN DSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-CBC,160DA53675A873B4

0FPgOgyus98i/UKSXNIh+H+tGvnKXKLZ+hn11QEIGWe5trYEihLJ1HktaotbtZcp
Dn3F/p9Pxokf4IGww+fiRItg1TCi+99U8Q8LwG+BuTEcAQKuo+SjDNmACHlFXtuG
+kHNJBnnr0dj5P+K1atb7zssvaZ/Yvb/mBRzJ/m+mS4lcCrWA0/wi6xeglxN+Jrk
wA39UaqfmQ7AGIqmP2WFp3dfswh+6ndva6Ajrw4C7xoO6OUZgoHk2WK4wVW2a53d
VmbdUyIjfohUQ/AeHHpnFt4N1x13K+StU0NXvpNiRbx+PmCLP9ITS+N1QGEEu77M
Q5k0zkAB/rRrCESsXQ5kwbYyk9wuv58RVDmencdY4rAQbopzzmegveT4cvqdFjMK
AhC8gMg2IgLg94VXUisAmwpJd2l5rLf5XjCrq3JhCMldt0jEZ+Mr7jPRtxhPDbH+
dWbAWVmAz/PjnloAkI8Iz2hChd6K0rRTysvS0q5uLVFXKbk+mCXvzhjfnj3T+Fwx
8G7X88tKJClkwpY+yFsROaPS3wHOFPewZpBB2Z+xSCgCIX7TVGz0twq+2cqasX9s
dJW8Z3Wgr9MUNVDV+sa6hA==
-----END DSA PRIVATE KEY-----"""


TEST_PEM_DES3_ENC = b"""-----BEGIN DSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,EF0656428C0FB402

kgFYYNtmg55/LutnArhEsMVBL37GvUL0QSlQsA6soAewohjXqOiB8w6mYQzterHT
Ox2ZPyWKVtXDLXR1YhHYr2931n/bp48QNhh0s0mRObjl1z6/nhVmth5kQ8o015tY
uXp6mRQW+aomgYsX05HrGxHMKIs9qfbKAwy9of4kY+fIzYSitPqiH7yHCq79fvO2
H/HB1rbswV1SrsaKLPDypB9IXs/NCWZU+1YMFnM3iLtcTQjIRNYM5hQIDhj9ULDA
DW66jTt2einwpSPwNFUjUeqHPSolyhpPqMjXl6IqSk8mudKUQ7isIEHcAkOoegeG
YKVggt4NOyL1+ZGavsPjTqRuI421nvFLaLZxq/UmvTQmgYQwHQQcrmYVbi5OdUDy
PzxPh3LM3azqDGSqrHpe0umHFVx1K34Jsu1Ficj/OXD6lsDNecVn9RaoU2nlSHPu
nUnPagC4NrDaANf6yo7TdirdLhvejMnsjB2RfJQYekqzU6HDg68mKavOTPzPANhW
hVUiRnlk7iqjDUNJDEvFL/u/50bgxUptd7yW+koK9BsxvDxq8SIm53MHHTJy+686
kRRBxzk5SiQAsSmYzHEsZQ==
-----END DSA PRIVATE KEY-----"""


# Test values and Known Answers
p, q, g = (89884656743115801690508003283032491320041051484130708380666508310605797591517657358448008016999203132296409109102891732381220932613670902301632476397501213820805847702280695479500940353078645163835996628341628828734609016397792501661682873394045725954243200605294871617235478335283698125903031997252753894013, 1207753555331593152985388036246139579485647958891, 5685459514059326809802874748014957316613560771138779799702167979852700053970957043705475419576800042124393749290154460175165016805439205742686078247106048259784394071586242286134792733247049365228417141823234012958591708840401400841693876682668942266225335842678094931739699394533691980318928257007905664651)
x, y = (25699150469538346273151504617195356896428318293, 87776125859689842027622448321257490281265790877998817249106298815115428969131775305386159545084670793191253582533101771837559797201510474157521867255147636248371470086721784879086813365664064382328859209285425076675844776906158328001899804552410472894735495394660855543401958332363658604533641691539985334580)
k = 707729718173049907897274687372338676901147366291
H = lambda msg: msg
message = int.from_bytes(b'\xf7\xff\x9e\x8b{\xb2\xe0\x9bp\x93Z]x^\x0c\xc5\xd9\xd0\xab\xf0', byteorder='big')
sig = (503181762231277455297502611450705228583240869840, 1148561876858258037434302178106550418252606972216)


class DSATestCase(unittest.TestCase):
    def hash(self, m):
        return m

    def setUp(self):
        dsa = DSA(self)
        dsa.p, dsa.q, dsa.g = p, q, g
        dsa.x, dsa.y = x, y

        self.dsa = dsa

    def test_dsa_sign(self):
        self.assertEqual(self.dsa.sign(message, k), sig)


    def test_dsa_verify(self):
        self.assertTrue(self.dsa.verify(message, sig))


    def test_k_derivation(self):
        messageB = int.from_bytes(hashlib.sha1(b'deadbeef').digest(), byteorder='big')
        sig_genB = self.dsa.sign(messageB, k)
        found_k = self.dsa.derive_k_from_sigs(message, sig, messageB, sig_genB)
        self.assertEqual(found_k, k)


    def test_x_derivation(self):
        self.dsa.x = 0
        self.dsa.x = self.dsa.derive_x_from_k(message, k, sig)
        self.assertEqual(self.dsa.x, x)



    def test_der_encode(self):
        for _ in range(20):
            dsa = DSA(None)

            should_pem_encode = Bytes.random(1).int() & 1

            der_bytes = dsa.export_private_key(should_pem_encode)
            recovered_dsa = DSA.import_key(der_bytes)

            self.assertEqual((dsa.p, dsa.q, dsa.g, dsa.x), (recovered_dsa.p, recovered_dsa.q, recovered_dsa.g, recovered_dsa.x))



    def test_import_export_private(self):
        dsa = DSA.import_key(TEST_PRIV)
        der_bytes = dsa.export_private_key()
        new_dsa = DSA.import_key(der_bytes)

        self.assertEqual((dsa.p, dsa.q, dsa.g, dsa.x), (new_dsa.p, new_dsa.q, new_dsa.g, new_dsa.x))
        self.assertEqual(der_bytes.replace(b'\n', b''), TEST_PRIV.replace(b'\n', b''))


    def test_import_export_public(self):
        dsa_pub  = DSA.import_key(TEST_PUB)
        dsa_priv = DSA.import_key(TEST_PRIV)

        der_bytes = dsa_pub.export_public_key()
        new_pub  = DSA.import_key(der_bytes)

        self.assertEqual((dsa_pub.p, dsa_pub.q, dsa_pub.g, dsa_pub.y), (dsa_priv.p, dsa_priv.q, dsa_priv.g, dsa_priv.y))
        self.assertEqual((new_pub.p, new_pub.q, new_pub.g, new_pub.y), (dsa_priv.p, dsa_priv.q, dsa_priv.g, dsa_priv.y))
        self.assertEqual(der_bytes.replace(b'\n', b''), TEST_PUB.replace(b'\n', b''))


    def _run_import_pem_enc(self, enc_priv):
        with self.assertRaises(ValueError):
            DSA.import_key(enc_priv)

        enc_dsa = DSA.import_key(enc_priv, PEM_PASSPHRASE)
        dec_dsa = DSA.import_key(TEST_PEM_DEC)
        self.assertEqual((enc_dsa.p, enc_dsa.q, enc_dsa.g, enc_dsa.y), (dec_dsa.p, dec_dsa.q, dec_dsa.g, dec_dsa.y))


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
        supported_algos = RFC1423_ALGOS.keys()
        for algo in supported_algos:
            for _ in range(10):
                dsa = DSA(None)
                key = Bytes.random(Bytes.random(1).int() + 1)
                enc_pem = dsa.export_private_key(encryption=algo, passphrase=key)
                dec_dsa = DSA.import_key(enc_pem, key)

                self.assertEqual((dsa.p, dsa.q, dsa.g, dsa.y), (dec_dsa.p, dec_dsa.q, dec_dsa.g, dec_dsa.y))



    def test_import_ssh(self):
        dsa_pub = DSA.import_key(TEST_SSH2_PUB)
        self.assertEqual(dsa_pub.p, 89884656743115795391714060562757515397425322659982333453951503557945186260897603074467021329267150667179270601498386514202185870349356296751727808353958732563710461587745543679948630665057517430779539542454135056582551841462788758130134369220761262066732236795930452718468922387238066961216943830683854773169)
        self.assertEqual(dsa_pub.q, 1398446195032410252040217410173702390108694920283)
        self.assertEqual(dsa_pub.g, 62741477437088172631393589185350035491867729832629398027831312004924312513744633269784278916027520183601208756530710011458232054971579879048852582591127008356159595963890332524237209902067360056459538632225446131921069339325466545201845714001580950381286256953162223728420823439838953735559776779136624763537)
        self.assertEqual(dsa_pub.y, 89304173996622136803697185034716185066873574928118988908946173912972803079394854332431645751271541413754929474728944725753979110082470431256515341756380336480154766674026631800266177718504673102950377953224324965826950742525966269191766953261195015149626105144609044917769140962813589211397528346030252275759)
