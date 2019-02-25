from samson.block_ciphers.rijndael import Rijndael
from samson.block_ciphers.modes.eax import EAX
from samson.utilities.bytes import Bytes
import unittest


# http://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf
class EAXTestCase(unittest.TestCase):
    def _run_test(self, key, plaintext, nonce, header, expected_ciphertext):
        rij = Rijndael(key)
        eax = EAX(rij, nonce)
        ciphertext  = eax.encrypt(plaintext, header)

        self.assertEqual(ciphertext, expected_ciphertext)
        self.assertEqual(eax.decrypt(ciphertext, header), plaintext)



    def test_vec0(self):
        key                 = Bytes(0x233952DEE4D5ED5F9B9C6D6FF80FF478).zfill(16)
        nonce               = Bytes(0x62EC67F9C3A4A407FCB2A8C49031A8B3)
        header              = Bytes(0x6BFB914FD07EAE6B)
        plaintext           = Bytes(b'')
        expected_ciphertext = Bytes(0xE037830E8389F27B025A2D6527E79D01)

        self._run_test(key, plaintext, nonce, header, expected_ciphertext)


    def test_vec1(self):
        key                 = Bytes(0x91945D3F4DCBEE0BF45EF52255F095A4).zfill(16)
        nonce               = Bytes(0xBECAF043B0A23D843194BA972C66DEBD)
        header              = Bytes(0xFA3BFD4806EB53FA)
        plaintext           = Bytes(0xF7FB)
        expected_ciphertext = Bytes(0x19DD5C4C9331049D0BDAB0277408F67967E5)

        self._run_test(key, plaintext, nonce, header, expected_ciphertext)


    def test_vec2(self):
        key                 = Bytes(0x01F74AD64077F2E704C0F60ADA3DD523).zfill(16)
        nonce               = Bytes(0x70C3DB4F0D26368400A10ED05D2BFF5E)
        header              = Bytes(0x234A3463C1264AC6)
        plaintext           = Bytes(0x1A47CB4933)
        expected_ciphertext = Bytes(0xD851D5BAE03A59F238A23E39199DC9266626C40F80)

        self._run_test(key, plaintext, nonce, header, expected_ciphertext)


    def test_vec3(self):
        key                 = Bytes(0xD07CF6CBB7F313BDDE66B727AFD3C5E8).zfill(16)
        nonce               = Bytes(0x8408DFFF3C1A2B1292DC199E46B7D617)
        header              = Bytes(0x33CCE2EABFF5A79D)
        plaintext           = Bytes(0x481C9E39B1)
        expected_ciphertext = Bytes(0x632A9D131AD4C168A4225D8E1FF755939974A7BEDE)

        self._run_test(key, plaintext, nonce, header, expected_ciphertext)


    def test_vec4(self):
        key                 = Bytes(0x35B6D0580005BBC12B0587124557D2C2).zfill(16)
        nonce               = Bytes(0xFDB6B06676EEDC5C61D74276E1F8E816)
        header              = Bytes(0xAEB96EAEBE2970E9)
        plaintext           = Bytes(0x40D0C07DA5E4)
        expected_ciphertext = Bytes(0x071DFE16C675CB0677E536F73AFE6A14B74EE49844DD)

        self._run_test(key, plaintext, nonce, header, expected_ciphertext)


    def test_vec5(self):
        key                 = Bytes(0xBD8E6E11475E60B268784C38C62FEB22).zfill(16)
        nonce               = Bytes(0x6EAC5C93072D8E8513F750935E46DA1B)
        header              = Bytes(0xD4482D1CA78DCE0F)
        plaintext           = Bytes(0x4DE3B35C3FC039245BD1FB7D)
        expected_ciphertext = Bytes(0x835BB4F15D743E350E728414ABB8644FD6CCB86947C5E10590210A4F)

        self._run_test(key, plaintext, nonce, header, expected_ciphertext)


    def test_vec6(self):
        key                 = Bytes(0x7C77D6E813BED5AC98BAA417477A2E7D).zfill(16)
        nonce               = Bytes(0x1A8C98DCD73D38393B2BF1569DEEFC19)
        header              = Bytes(0x65D2017990D62528)
        plaintext           = Bytes(0x8B0A79306C9CE7ED99DAE4F87F8DD61636)
        expected_ciphertext = Bytes(0x02083E3979DA014812F59F11D52630DA30137327D10649B0AA6E1C181DB617D7F2)

        self._run_test(key, plaintext, nonce, header, expected_ciphertext)


    def test_vec7(self):
        key                 = Bytes(0xA4A4782BCFFD3EC5E7EF6D8C34A56123).zfill(16)
        nonce               = Bytes(0xB781FCF2F75FA5A8DE97A9CA48E522EC)
        header              = Bytes(0x899A175897561D7E)
        plaintext           = Bytes(0x6CF36720872B8513F6EAB1A8A44438D5EF11)
        expected_ciphertext = Bytes(0x0DE18FD0FDD91E7AF19F1D8EE8733938B1E8E7F6D2231618102FDB7FE55FF1991700)

        self._run_test(key, plaintext, nonce, header, expected_ciphertext)


    def test_vec8(self):
        key                 = Bytes(0x5FFF20CAFAB119CA2FC73549E20F5B0D).zfill(16)
        nonce               = Bytes(0xDDE59B97D722156D4D9AFF2BC7559826)
        header              = Bytes(0x54B9F04E6A09189A)
        plaintext           = Bytes(0x1BDA122BCE8A8DBAF1877D962B8592DD2D56)
        expected_ciphertext = Bytes(0x2EC47B2C4954A489AFC7BA4897EDCDAE8CC33B60450599BD02C96382902AEF7F832A)

        self._run_test(key, plaintext, nonce, header, expected_ciphertext)


    def test_vec9(self):
        key                 = Bytes(0x8395FCF1E95BEBD697BD010BC766AAC3).zfill(16)
        nonce               = Bytes(0x22E7ADD93CFC6393C57EC0B3C17D6B44)
        header              = Bytes(0x126735FCC320D25A)
        plaintext           = Bytes(0xCA40D7446E545FFAED3BD12A740A659FFBBB3CEAB7)
        expected_ciphertext = Bytes(0xCB8920F87A6C75CFF39627B56E3ED197C552D295A7CFC46AFC253B4652B1AF3795B124AB6E)

        self._run_test(key, plaintext, nonce, header, expected_ciphertext)
