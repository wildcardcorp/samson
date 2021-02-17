from samson.utilities.bytes import Bytes
from samson.prngs.all import MWC1616, MWC, Xoroshiro116Plus, Xoroshiro128Plus, Xorshift32, Xorshift64, Xorshift128, PCG, Xorshift1024Star, LFG, Xoshiro256PlusPlus, Xoshiro128PlusPlus
from samson.core.prng import PRNG
import unittest


class ReverseClockTestCase(unittest.TestCase):
    def test_reverse_clocks(self):
        prngs = [
            MWC1616([Bytes.random(4).int() for _ in range(2)]),
            Xoroshiro116Plus([4039333298297189104, 14574314857804983261]),
            Xoroshiro128Plus([Bytes.random(8).int() for _ in range(2)]),
            Xorshift32([Bytes.random(4).int()]),
            Xorshift64([Bytes.random(8).int()]),
            Xorshift128([Bytes.random(4).int() for _ in range(4)]),
            PCG(seed=0x4d595df4d0f33173, multiplier=6364136223846793005, increment=1442695040888963407),
            PRNG.GO[LFG]([Bytes.random(8).int() for _ in range(607)]),
            Xorshift1024Star([
                1777391367797874666, 1964529382746821925, 7996041688159811731,
                16797603918550466679, 13239206057622895956, 2190120427146910527,
                18292739386017762693, 7995684206500985125, 1619687243448614582,
                961993414031414042, 10239938031393579756, 12249841489256032092,
                1457887945073169212, 16031477380367994289, 12526413104181201380,
                16202025130717851397
            ]),
            Xoshiro256PlusPlus([Bytes.random(8).int() for _ in range(4)]),
            Xoshiro128PlusPlus([Bytes.random(4).int() for _ in range(4)]),
            MWC([Bytes.random(4).int() for _ in range(2)])
        ]

        for prng in prngs:
            a = [prng.generate() for _ in range(5000)]
            b = [prng.reverse_clock() for _ in range(5000)]
            self.assertEqual(a[::-1][1:], b[:-1])
