from samson.stream_ciphers.salsa import Salsa
from samson.utilities.bytes import Bytes
import unittest

# http://www.ecrypt.eu.org/stream/svn/viewcvs.cgi/ecrypt/trunk/submissions/salsa20/full/verified.test-vectors?rev=161
class SalsaTestCase(unittest.TestCase):
    def _run_test(self, key, nonce, expected_ciphertext):
        salsa = Salsa(key, nonce)
        keystream_chunks = list(salsa.yield_state(0,  5))

        self.assertEqual(keystream_chunks[0], expected_ciphertext[0])

        if len(expected_ciphertext) > 1:
            self.assertEqual(keystream_chunks[3], expected_ciphertext[1])
            self.assertEqual(keystream_chunks[4], expected_ciphertext[2])



    def test_vec0(self):
        key                 = Bytes(0x8000000000000000000000000000000000000000000000000000000000000000).zfill(32)
        nonce               = Bytes(0x0000000000000000).zfill(8)
        expected_ciphertext = [
            Bytes(0xE3BE8FDD8BECA2E3EA8EF9475B29A6E7003951E1097A5C38D23B7A5FAD9F6844B22C97559E2723C7CBBD3FE4FC8D9A0744652A83E72A9C461876AF4D7EF1A117),
            Bytes(0x57BE81F47B17D9AE7C4FF15429A73E10ACF250ED3A90A93C711308A74C6216A9ED84CD126DA7F28E8ABF8BB63517E1CA98E712F4FB2E1A6AED9FDC73291FAA17),
            Bytes(0x958211C4BA2EBD5838C635EDB81F513A91A294E194F1C039AEEC657DCE40AA7E7C0AF57CACEFA40C9F14B71A4B3456A63E162EC7D8D10B8FFB1810D71001B618)
        ]

        self._run_test(key, nonce, expected_ciphertext)



    def test_vec1(self):
        key                 = Bytes(0xBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDC).zfill(32)
        nonce               = Bytes(0x0000000000000000).zfill(8)
        expected_ciphertext = [
            Bytes(0x1D8D3CB0B17972779FBD8339BDBC5D0C4178C943381AFA6FA974FF792C78B4BB5E0D8A2D2F9988C01F0FF7CE8AD310B66FA3B8D8CB507E507C4516BC9E7603B6),
            Bytes(0xF32D0691B1832478889516518C441ADB8F0FE2165B15043756BB37928EBCA33F9C166A5907F7F85CCF45CE6BFB68E725748FA39528149A0E96B0B6C656854F88),
            Bytes(0x66A7226EA4CF4DB203592F0C678BA8D299F26E212F2874681E29426A579469B2CA747B8620E7E48A7E77D50E5C45FF62A733D6052B2FB4AAB4AC782539193A76)
        ]

        self._run_test(key, nonce, expected_ciphertext)



    def test_vec2(self):
        key                 = Bytes(0x0).zfill(32)
        nonce               = Bytes(0x8000000000000000).zfill(8)
        expected_ciphertext = [
            Bytes(0x2ABA3DC45B4947007B14C851CD694456B303AD59A465662803006705673D6C3E29F1D3510DFC0405463C03414E0E07E359F1F1816C68B2434A19D3EEE0464873),
            Bytes(0xEFF0C107DCA563B5C0048EB488B40341ED34052790475CD204A947EB480F3D753EF5347CEBB0A21F25B6CC8DE6B48906E604F554A6B01B23791F95C4A93A4717),
            Bytes(0xE3393E1599863B52DE8C52CF26C752FB473B74A34D6D9FE31E9CA8DD6292522F13EB456C5BE9E5432C06E1BA3965D45448936BC98376BF903969F049347EA05D)
        ]

        self._run_test(key, nonce, expected_ciphertext)




    def test_vec3(self):
        key                 = Bytes(0x0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D).zfill(32)
        nonce               = Bytes(0x0D74DB42A91077DE).zfill(8)
        expected_ciphertext = [
            Bytes(0xF5FAD53F79F9DF58C4AEA0D0ED9A9601F278112CA7180D565B420A48019670EAF24CE493A86263F677B46ACE1924773D2BB25571E1AA8593758FC382B1280B71)
        ]

        self._run_test(key, nonce, expected_ciphertext)


    # Test random-access
    def test_vec4(self):
        key                 = Bytes(0x0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D).zfill(32)
        nonce               = Bytes(0x0D74DB42A91077DE).zfill(8)
        expected_ciphertext = Bytes(0xB70C50139C63332EF6E77AC54338A4079B82BEC9F9A403DFEA821B83F7860791650EF1B2489D0590B1DE772EEDA4E3BCD60FA7CE9CD623D9D2FD5758B8653E70)

        salsa = Salsa(key, nonce)
        keystream_chunks = list(salsa.yield_state(1023,  1))

        self.assertEqual(keystream_chunks[0], expected_ciphertext)
