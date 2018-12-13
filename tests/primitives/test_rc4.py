import unittest
from samson.utilities.bytes import Bytes
from samson.stream_ciphers.rc4 import RC4
import codecs

# https://tools.ietf.org/html/rfc6229#page-4

TEST_KEY_0 = Bytes(0x01020304050607)

TEST_VEC_0 = b"""29 3f 02 d4  7f 37 c9 b6   33 f2 af 52  85 fe b4 6b
e6 20 f1 39  0d 19 bd 84   e2 e0 fd 75  20 31 af c1
91 4f 02 53  1c 92 18 81   0d f6 0f 67  e3 38 15 4c
d0 fd b5 83  07 3c e8 5a   b8 39 17 74  0e c0 11 d5
75 f8 14 11  e8 71 cf fa   70 b9 0c 74  c5 92 e4 54
0b b8 72 02  93 8d ad 60   9e 87 a5 a1  b0 79 e5 e4
c2 91 12 46  b6 12 e7 e7   b9 03 df ed  a1 da d8 66
32 82 8f 91  50 2b 62 91   36 8d e8 08  1d e3 6f c2
f3 b9 a7 e3  b2 97 bf 9a   d8 04 51 2f  90 63 ef f1
8e cb 67 a9  ba 1f 55 a5   a0 67 e2 b0  26 a3 67 6f
d2 aa 90 2b  d4 2d 0d 7c   fd 34 0c d4  58 10 52 9f
78 b2 72 c9  6e 42 ea b4   c6 0b d9 14  e3 9d 06 e3
f4 33 2f d3  1a 07 93 96   ee 3c ee 3f  2a 4f f0 49
05 45 97 81  d4 1f da 7f   30 c1 be 7e  12 46 c6 23
ad fd 38 68  b8 e5 14 85   d5 e6 10 01  7e 3d d6 09
ad 26 58 1c  0c 5b e4 5f   4c ea 01 db  2f 38 05 d5
f3 17 2c ef  fc 3b 3d 99   7c 85 cc d5  af 1a 95 0c
e7 4b 0b 97  31 22 7f d3   7c 0e c0 8a  47 dd d8 b8""".replace(b' ', b'').split(b'\n')

TEST_KEY_1 = Bytes(0x0102030405060708)

TEST_VEC_1 = b""" 97 ab 8a 1b  f0 af b9 61   32 f2 f6 72  58 da 15 a8
82 63 ef db  45 c4 a1 86   84 ef 87 e6  b1 9e 5b 09
96 36 eb c9  84 19 26 f4   f7 d1 f3 62  bd df 6e 18
d0 a9 90 ff  2c 05 fe f5   b9 03 73 c9  ff 4b 87 0a
73 23 9f 1d  b7 f4 1d 80   b6 43 c0 c5  25 18 ec 63
16 3b 31 99  23 a6 bd b4   52 7c 62 61  26 70 3c 0f
49 d6 c8 af  0f 97 14 4a   87 df 21 d9  14 72 f9 66
44 17 3a 10  3b 66 16 c5   d5 ad 1c ee  40 c8 63 d0
27 3c 9c 4b  27 f3 22 e4   e7 16 ef 53  a4 7d e7 a4
c6 d0 e7 b2  26 25 9f a9   02 34 90 b2  61 67 ad 1d
1f e8 98 67  13 f0 7c 3d   9a e1 c1 63  ff 8c f9 d3
83 69 e1 a9  65 61 0b e8   87 fb d0 c7  91 62 aa fb
0a 01 27 ab  b4 44 84 b9   fb ef 5a bc  ae 1b 57 9f
c2 cd ad c6  40 2e 8e e8   66 e1 f3 7b  db 47 e4 2c
26 b5 1e a3  7d f8 e1 d6   f7 6f c3 b6  6a 74 29 b3
bc 76 83 20  5d 4f 44 3d   c1 f2 9d da  33 15 c8 7b
d5 fa 5a 34  69 d2 9a aa   f8 3d 23 58  9d b8 c8 5b
3f b4 6e 2c  8f 0f 06 8e   dc e8 cd cd  7d fc 58 62""".replace(b' ', b'').split(b'\n')


TEST_KEY_2 = Bytes(0x0102030405060708090a)

TEST_VEC_2 = b"""ed e3 b0 46  43 e5 86 cc   90 7d c2 18  51 70 99 02
03 51 6b a7  8f 41 3b eb   22 3a a5 d4  d2 df 67 11
3c fd 6c b5  8e e0 fd de   64 01 76 ad  00 00 04 4d
48 53 2b 21  fb 60 79 c9   11 4c 0f fd  9c 04 a1 ad
3e 8c ea 98  01 71 09 97   90 84 b1 ef  92 f9 9d 86
e2 0f b4 9b  db 33 7e e4   8b 8d 8d c0  f4 af ef fe
5c 25 21 ea  cd 79 66 f1   5e 05 65 44  be a0 d3 15
e0 67 a7 03  19 31 a2 46   a6 c3 87 5d  2f 67 8a cb
a6 4f 70 af  88 ae 56 b6   f8 75 81 c0  e2 3e 6b 08
f4 49 03 1d  e3 12 81 4e   c6 f3 19 29  1f 4a 05 16
bd ae 85 92  4b 3c b1 d0   a2 e3 3a 30  c6 d7 95 99
8a 0f ed db  ac 86 5a 09   bc d1 27 fb  56 2e d6 0a
b5 5a 0a 5b  51 a1 2a 8b   e3 48 99 c3  e0 47 51 1a
d9 a0 9c ea  3c e7 5f e3   96 98 07 03  17 a7 13 39
55 22 25 ed  11 77 f4 45   84 ac 8c fa  6c 4e b5 fc
7e 82 cb ab  fc 95 38 1b   08 09 98 44  21 29 c2 f8
1f 13 5e d1  4c e6 0a 91   36 9d 23 22  be f2 5e 3c
08 b6 be 45  12 4a 43 e2   eb 77 95 3f  84 dc 85 53""".replace(b' ', b'').split(b'\n')


TEST_KEY_3 = Bytes(0x0102030405060708090a0b0c0d0e0f10)

TEST_VEC_3 = b"""9a c7 cc 9a  60 9d 1e f7   b2 93 28 99  cd e4 1b 97
52 48 c4 95  90 14 12 6a   6e 8a 84 f1  1d 1a 9e 1c
06 59 02 e4  b6 20 f6 cc   36 c8 58 9f  66 43 2f 2b
d3 9d 56 6b  c6 bc e3 01   07 68 15 15  49 f3 87 3f
b6 d1 e6 c4  a5 e4 77 1c   ad 79 53 8d  f2 95 fb 11
c6 8c 1d 5c  55 9a 97 41   23 df 1d bc  52 a4 3b 89
c5 ec f8 8d  e8 97 fd 57   fe d3 01 70  1b 82 a2 59
ec cb e1 3d  e1 fc c9 1c   11 a0 b2 6c  0b c8 fa 4d
e7 a7 25 74  f8 78 2a e2   6a ab cf 9e  bc d6 60 65
bd f0 32 4e  60 83 dc c6   d3 ce dd 3c  a8 c5 3c 16
b4 01 10 c4  19 0b 56 22   a9 61 16 b0  01 7e d2 97
ff a0 b5 14  64 7e c0 4f   63 06 b8 92  ae 66 11 81
d0 3d 1b c0  3c d3 3d 70   df f9 fa 5d  71 96 3e bd
8a 44 12 64  11 ea a7 8b   d5 1e 8d 87  a8 87 9b f5
fa be b7 60  28 ad e2 d0   e4 87 22 e4  6c 46 15 a3
c0 5d 88 ab  d5 03 57 f9   35 a6 3c 59  ee 53 76 23
ff 38 26 5c  16 42 c1 ab   e8 d3 c2 fe  5e 57 2b f8
a3 6a 4c 30  1a e8 ac 13   61 0c cb c1  22 56 ca cc""".replace(b' ', b'').split(b'\n')


TEST_KEY_4 = Bytes(0x0102030405060708090a0b0c0d0e0f101112131415161718)

TEST_VEC_4 = b"""05 95 e5 7f  e5 f0 bb 3c   70 6e da c8  a4 b2 db 11
df de 31 34  4a 1a f7 69   c7 4f 07 0a  ee 9e 23 26
b0 6b 9b 1e  19 5d 13 d8   f4 a7 99 5c  45 53 ac 05
6b d2 37 8e  c3 41 c9 a4   2f 37 ba 79  f8 8a 32 ff
e7 0b ce 1d  f7 64 5a db   5d 2c 41 30  21 5c 35 22
9a 57 30 c7  fc b4 c9 af   51 ff da 89  c7 f1 ad 22
04 85 05 5f  d4 f6 f0 d9   63 ef 5a b9  a5 47 69 82
59 1f c6 6b  cd a1 0e 45   2b 03 d4 55  1f 6b 62 ac
27 53 cc 83  98 8a fa 3e   16 88 a1 d3  b4 2c 9a 02
93 61 0d 52  3d 1d 3f 00   62 b3 c2 a3  bb c7 c7 f0
96 c2 48 61  0a ad ed fe   af 89 78 c0  3d e8 20 5a
0e 31 7b 3d  1c 73 b9 e9   a4 68 8f 29  6d 13 3a 19
bd f0 e6 c3  cc a5 b5 b9   d5 33 b6 9c  56 ad a1 20
88 a2 18 b6  e2 ec e1 e6   24 6d 44 c7  59 d1 9b 10
68 66 39 7e  95 c1 40 53   4f 94 26 34  21 00 6e 40
32 cb 0a 1e  95 42 c6 b3   b8 b3 98 ab  c3 b0 f1 d5
29 a0 b8 ae  d5 4a 13 23   24 c6 2e 42  3f 54 b4 c8
3c b0 f3 b5  02 0a 98 b8   2a f9 fe 15  44 84 a1 68""".replace(b' ', b'').split(b'\n')


TEST_KEY_5 = Bytes(0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20)

TEST_VEC_5 = b"""ea a6 bd 25  88 0b f9 3d   3f 5d 1e 4c  a2 61 1d 91
cf a4 5c 9f  7e 71 4b 54   bd fa 80 02  7c b1 43 80
11 4a e3 44  de d7 1b 35   f2 e6 0f eb  ad 72 7f d8
02 e1 e7 05  6b 0f 62 39   00 49 64 22  94 3e 97 b6
91 cb 93 c7  87 96 4e 10   d9 52 7d 99  9c 6f 93 6b
49 b1 8b 42  f8 e8 36 7c   be b5 ef 10  4b a1 c7 cd
87 08 4b 3b  a7 00 ba de   95 56 10 67  27 45 b3 74
e7 a7 b9 e9  ec 54 0d 5f   f4 3b db 12  79 2d 1b 35
c7 99 b5 96  73 8f 6b 01   8c 76 c7 4b  17 59 bd 90
7f ec 5b fd  9f 9b 89 ce   65 48 30 90  92 d7 e9 58
40 f2 50 b2  6d 1f 09 6a   4a fd 4c 34  0a 58 88 15
3e 34 13 5c  79 db 01 02   00 76 76 51  cf 26 30 73
f6 56 ab cc  f8 8d d8 27   02 7b 2c e9  17 d4 64 ec
18 b6 25 03  bf bc 07 7f   ba bb 98 f2  0d 98 ab 34
8a ed 95 ee  5b 0d cb fb   ef 4e b2 1d  3a 3f 52 f9
62 5a 1a b0  0e e3 9a 53   27 34 6b dd  b0 1a 9c 18
a1 3a 7c 79  c7 e1 19 b5   ab 02 96 ab  28 c3 00 b9
f3 e4 c0 a2  e0 2d 1d 01   f7 f0 a7 46  18 af 2b 48""".replace(b' ', b'').split(b'\n')

class RC4TestCase(unittest.TestCase):
    def _run_test(self, key, test_vec):
        rc4 = RC4(key)
        keystream = rc4.generate(4112)

        for i, start in enumerate([0, 16, 240, 256, 496, 512, 752, 768, 1008, 1024, 1520, 1536, 2032, 2048, 3056, 3072, 4080, 4096]):
            self.assertEqual(keystream[start:start + 16], codecs.decode(test_vec[i], 'hex_codec'))


    def test_vec0(self):
        self._run_test(TEST_KEY_0, TEST_VEC_0)


    def test_vec1(self):
        self._run_test(TEST_KEY_1, TEST_VEC_1)


    def test_vec2(self):
        self._run_test(TEST_KEY_2, TEST_VEC_2)


    def test_vec3(self):
        self._run_test(TEST_KEY_3, TEST_VEC_3)


    def test_vec4(self):
        self._run_test(TEST_KEY_4, TEST_VEC_4)


    def test_vec5(self):
        self._run_test(TEST_KEY_5, TEST_VEC_5)
