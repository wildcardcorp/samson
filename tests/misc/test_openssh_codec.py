from samson.encoding.openssh.openssh_rsa_key import OpenSSHRSAKey
from samson.encoding.openssh.rsa_public_key import RSAPublicKey
from samson.encoding.pem import pem_decode
from base64 import b64decode
import unittest


class OpenSSHCodecTestCase(unittest.TestCase):
    def _run_priv_test(self, openssh_key, passphrase=None):
        parsed_key = OpenSSHRSAKey.unpack(openssh_key, passphrase=passphrase)
        packed = parsed_key.pack(passphrase=passphrase)
        self.assertEqual(packed, openssh_key)


    def _run_pub_test(self, openssh_key):
        parsed_key, _ = RSAPublicKey.unpack(openssh_key, already_unpacked=True)
        self.assertEqual(RSAPublicKey.pack(parsed_key)[4:], openssh_key)


    def test_vec0(self):
        enc_rsa = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABC3OI9y/7
XkcWYsp75ZQNg+AAAAEAAAAAEAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQDEkJ8gu8Ka
OrlokS0bVSsuUQ5m+mDvllZKc0rni6uGDn6njzg43U+Rco077M0y3CGnD9ESrsaHwI5ltS
fx9zceRlinwDma0rVPajfDq7Yh/xk3N2WlBio4nRNF4bPtZIA0vR842PisyKSn9RrF/iR8
9KUzaabEQpGkWGWJrHiGg/h3H4yJBGX9xm+tPU3nFoTj2gjHZTLvEBuSWfYtLnbqmW8Ar9
+zbCs3eUge7T7tCUPmqFMTKXN6N5rFtkoS2WGP2to7OLEXqWoSnMame3Z4UriBj4gbf13x
NVzVUnshwVqkEVz1pDJva0nSMVs1wU4xIm2rzku6hTOcuALF9nElAAAD0JUm6Sr05geQlR
n/VIJ95PW3PUh1qHVcF7TLoSfIkhfcuaS7PtcXyHmQJ+YWmCpGpGTZC/pzY79LXDPGIbcr
K0AjgX6XVKUfgA6H0zZhBHN8H2rNn3IkH9vMh5ENuhMGZYwKNiEirgGbaJNRlJTY5mzVdd
EK7r3asSkn3LdcwqEkuhK6+denGzeMK81eQS2VDrhcv9Djfz0vu4NOFbw68o+oRPeLQ2xO
1MXPCqmTyodfSNPYA2H0Csn3dJqi7aLxNxcpRv1zanc3SM1GREJ36kD70VzoZ9nJgTNiIt
kl10jzY8++WYjz8oAfCs1tFI3ccKC9KmF7E9CtAOBcI9xN84Eb/dpKl5Of2sU6puhYu+sy
xZFfCeE4D2VfI5nNKxrupA8ESxaQwsWmjgws7RrZ+jeLsB0gy+U3XQ6bnXk5gCD66mFN0R
DlYrZxqT3nRh9oIppAo0q6AOB1HiIhQtHD43K/GiKs7JlYnBPkOGX6JsbSeqhakRcQ6lGP
mtWaRITF0zfQxIiW/rkQHcNu8/VQeWKcz3ea+faXzNBG1gvjXYOyifPbA1wKpDWBB40698
UTnf62QR5DG/EqUORrWZ0Q4LhtiFWfDb5YDp3KIJ8NZapkgiMDoEvyddPh3xGK+LhtxZ9F
tTJQGY5+xcjSgM77CGrQSVKBG8NBw8sOdbGM9z3hLVmz7LveQT8hgwYs4q94jUsAMKCKz4
iDLNYqUNypyUcUcLeaDj77HkN/i7q/PpKr1ykEoDz9z+evnniuFZJvKmus5NTTs3dnI1Gr
hIwCcGF/R1QOV6UZnUxBRuvfa/8xXzPDa5j1bTObkNT89jOXSpfvfq1SKfiHHeTFkByQq8
s1LoLUd5aQ722OI9Atl0P23pTeLrI3QHn09Eu9S1DhxHO0Dw8a7PeXgOE2IkYBX1JfyWs1
Sq72jO057AwTyhH58DkbQZ24yHNw0Y6fkVGQ6nSlFEO9BvBvgw2wT1Au8UcGzQvBAr2xZW
z/n2+K0pkgjLLpsTJWCuLLnqirgljRfc/JgJ/eS0ZgTv5716SM04uT0A/GCkLIBEE5tWJO
OMaG4x7k8iOIelHkvwUeb8FscLvV13IU1aCxbNQhHrTziupEyL5VK9Dnung5nwF0Jw/nKr
rr4Te/DCawEIb/TQQrOZ9krFKKew+Y8z2Cjv02tPvQx+G+WJBDQ56RRMCAfmbfdLX+Ks5u
5tshY6hFICd/aoQUh1GChuBy4ME88WEL/9vpNj6KGZ8RR8IB9QfDCFRNqvXEXyHGexgRCA
7s6/e1jqadOkrWct67dkl+P+28IR0=
-----END OPENSSH PRIVATE KEY-----"""

        # Watch out for the spelling mistake in the key
        self._run_priv_test(pem_decode(enc_rsa), b'super secret passhphrase')


    def test_vec1(self):
        enc_rsa = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAgZYxVX3
wNr/2tmsTgRd25AAAAEAAAAAEAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQCcvbb8PXGg
Ohb/T8qHun2JcBjWVJnHepDyQnlfjjqrwpsjqJQ8a0qQ8+dxXuO+B3fYc22Gt1Nr4t3fNS
U21sRmxrR/em1WRh6Wc+7Nj/tFv9nsFh0tvYP5pDPsI+sFRt1mnxGaHy5EXwuxkPgDr/Ak
dvCaicwzuxXpsdwQQ+6om0NXiCjfp9qhd80TnQdmlrATJTXdYyFaysIf8HWQRxGUSQzwhe
J6nU+eOmTqpMVlfQ03LM676OZAztDiqbONg3xQb07n/BK2UY3OZtmebqZgsUw4Ajg+LMxI
O1fCTSVFI+GEvhW0ZmaXtFw2N8NveRKJ3gfM9ugVY7YvXdVdNYfJAAAD0FDG2FqPhIkK+0
W94eEM8+OjIi8C+VV677Ft+1x9BJL4rybawpOoMvTTKPdQB0RwxAUaglPVSyDUL/gRvnv3
gAeAW2PXToOKbxAm2GcfvZbaLl4re9pGrNiUPP92iw9F20w8/KcQ3r5sy1xdSN1mb1W/76
7c2OhTliCbWQS5s1WjDuZ3J9+ppVwwOTzWwqyWT3G1zNoE1pDquM2yiR11iulWD1sJN6n9
4L+2NO52ckuT76WpPUO8Qi1BKhjmY+UyVQNOUOdi0GujRCtA91ww+SIH7dRZIyDQ1N1Lma
IvWl35vFXbP0nSlkDlm5SlwOnjQhmpfBpvJdC+QmpoeX8GIDVn16lkI2FIxtOTqDvBoYmj
AHdB2GK0KkZjA68Dox7AqTQKuGcTXuPKHiTRV2tpZn4kFmOzpoDm1DdyRwIZI4QjrgoLCN
vyakSLRW5drCdiKxMrBFiXC7hvTA4RM8fxdnDFxxwwkfbXFR7ey7HRKVLl3I1Pua6/y2MW
0kN1g9Fceq+WTpfPaAgf8CP5uyFRZGZeZb6E8uRWJGw9K8bpKQ5ufwYJzCVqyXCOTJmHwY
PmpT4QkEvh1Sro4WGibxQCCPuzo0JD8A7fWpMCe/1G8dCp78wj44ETg+bWIKKt3KnErHG9
uBh2y/ADMQv3uxBgHEZzVcq/YprgCW+rVj8W56QsRjZHu4mGNdZ+P0tDOVNlAHu8wwEAFg
ic+kFRB+JBSJbKT0nnxE3Dzb+O3zD925fS0WNRtYJ+ROp/sLwAD7xSEX+0SNsVrhmwQNHl
Po9y971t6M/Kd0kQqENz8xdqo2oKqTOvH24V8PHl3RgNmgHvkGNlPl9/UvXL0V1zdpHD2U
wnRQsGzNiX1LXQFERNGsOEb5ufs0LL07mdV3IuRwlbjnAZVrXU8Iri5pB30qZrlAllIW+b
3Ws+/fQIrMbDb005IRcJqHAUxMuC5YThZgdfsfMRM9F3tH4ryQ4FnW6Rzj4lRp01NWPBAd
DoSYdKvM1oW4J4G6SKfaDiRDYXoCpmPguFCLkdx7gmNU7gWY8XpoH2aAyLjPFGKJLXocyQ
nomsz7oByQzm779FDFMIsqvz7nIzAMxvKSLujkF74wPktbyHlniNNsYa5AJaw0fkMIYtUF
srbmJZmyR0f2z8NHvBSTweOfVgWe+xyzPxe+ysg7ObtF63TtsRx5pjPXxMEooDJj+7hcJ0
E0ahS5viCRC2MF/lzGYp2MV9NtARE1piRUh3M34qzmbQUXjV6Z0YRU4b6zWx6Q+3RcBGY/
5zYQA2HyylyosDPH2KZovi6k3pe60=
-----END OPENSSH PRIVATE KEY-----"""

        self._run_priv_test(pem_decode(enc_rsa), b'qwertyuiop')


    def test_vec2(self):
        enc_rsa = b"AAAAB3NzaC1yc2EAAAADAQABAAABAQCcvbb8PXGgOhb/T8qHun2JcBjWVJnHepDyQnlfjjqrwpsjqJQ8a0qQ8+dxXuO+B3fYc22Gt1Nr4t3fNSU21sRmxrR/em1WRh6Wc+7Nj/tFv9nsFh0tvYP5pDPsI+sFRt1mnxGaHy5EXwuxkPgDr/AkdvCaicwzuxXpsdwQQ+6om0NXiCjfp9qhd80TnQdmlrATJTXdYyFaysIf8HWQRxGUSQzwheJ6nU+eOmTqpMVlfQ03LM676OZAztDiqbONg3xQb07n/BK2UY3OZtmebqZgsUw4Ajg+LMxIO1fCTSVFI+GEvhW0ZmaXtFw2N8NveRKJ3gfM9ugVY7YvXdVdNYfJ"
        self._run_pub_test(b64decode(enc_rsa))
