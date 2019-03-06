from samson.utilities.bytes import Bytes
from samson.block_ciphers.camellia import Camellia
import unittest

class CamelliaTestCase(unittest.TestCase):
    # Ensures the cipher always outputs its block size
    def test_zfill(self):
        cipher_obj = Camellia(Bytes(0x8000000000000000).zfill(16))
        plaintext = Bytes(b'').zfill(16)
        ciphertext1 = cipher_obj.encrypt(plaintext)
        ciphertext2 = cipher_obj.decrypt(plaintext)

        self.assertEqual(cipher_obj.decrypt(ciphertext1), plaintext)
        self.assertEqual(cipher_obj.encrypt(ciphertext2), plaintext)


    def _run_test(self, key, plaintext, expected_ciphertext, expected_100_times):
        camellia = Camellia(key)
        ciphertext = camellia.encrypt(plaintext)

        self.assertEqual(ciphertext, expected_ciphertext)
        self.assertEqual(camellia.decrypt(ciphertext), plaintext)

        for _ in range(99):
            ciphertext = camellia.encrypt(ciphertext)

        self.assertEqual(ciphertext, expected_100_times)

        decypted = ciphertext
        for _ in range(100):
            decypted = camellia.decrypt(decypted)

        self.assertEqual(decypted, plaintext)



    # https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/camellia/Camellia-128-128.verified.test-vectors
    def test_vec_0(self):
        key                 = Bytes(0x80000000000000000000000000000000).zfill(16)
        plaintext           = Bytes(0x00000000000000000000000000000000).zfill(16)
        expected_ciphertext = Bytes(0x6C227F749319A3AA7DA235A9BBA05A2C).zfill(16)
        expected_100_times  = Bytes(0xF77AEC22A6043FE27A3BCB861C4BB0AC).zfill(16)

        self._run_test(key, plaintext, expected_ciphertext, expected_100_times)


    def test_vec_1(self):
        key                 = Bytes(0x40000000000000000000000000000000).zfill(16)
        plaintext           = Bytes(0x00000000000000000000000000000000).zfill(16)
        expected_ciphertext = Bytes(0xF04D51E45E70FB6DEE0D16A204FBBA16).zfill(16)
        expected_100_times  = Bytes(0xFF2DF2C65E9EAC360A31B2C42092751D).zfill(16)

        self._run_test(key, plaintext, expected_ciphertext, expected_100_times)


    def test_vec_2(self):
        key                 = Bytes(0x20000000000000000000000000000000).zfill(16)
        plaintext           = Bytes(0x00000000000000000000000000000000).zfill(16)
        expected_ciphertext = Bytes(0xED44242E619F8C32EAA2D3641DA47EA4).zfill(16)
        expected_100_times  = Bytes(0x44A582BEA5A09328C5B9ACF441514C3A).zfill(16)

        self._run_test(key, plaintext, expected_ciphertext, expected_100_times)


    def test_vec_3(self):
        key                 = Bytes(0x10000000000000000000000000000000).zfill(16)
        plaintext           = Bytes(0x00000000000000000000000000000000).zfill(16)
        expected_ciphertext = Bytes(0xAC640BBBF84CD3B8E8258BF66C210AE2).zfill(16)
        expected_100_times  = Bytes(0xC5E3EFED83AF022CD5BBDE07074B710D).zfill(16)

        self._run_test(key, plaintext, expected_ciphertext, expected_100_times)


    def test_vec_4(self):
        key                 = Bytes(0x00000000000000000000000000000000).zfill(16)
        plaintext           = Bytes(0x80000000000000000000000000000000).zfill(16)
        expected_ciphertext = Bytes(0x07923A39EB0A817D1C4D87BDB82D1F1C).zfill(16)
        expected_100_times  = Bytes(0xB2046F50D9D08A1B17468D44886033DF).zfill(16)

        self._run_test(key, plaintext, expected_ciphertext, expected_100_times)


    def test_vec_5(self):
        key                 = Bytes(0x00000000000000000000000000000000).zfill(16)
        plaintext           = Bytes(0x40000000000000000000000000000000).zfill(16)
        expected_ciphertext = Bytes(0x48CD6419809672D2349260D89A08D3D3).zfill(16)
        expected_100_times  = Bytes(0x587B1281ADA2D614F6C3D5386536ABFE).zfill(16)

        self._run_test(key, plaintext, expected_ciphertext, expected_100_times)


    def test_vec_6(self):
        key                 = Bytes(0x00000000000000000000000000000000).zfill(16)
        plaintext           = Bytes(0x20000000000000000000000000000000).zfill(16)
        expected_ciphertext = Bytes(0xD07493CCB2E95CE0B4945A05ACC97D82).zfill(16)
        expected_100_times  = Bytes(0x27E55F16A5C884CACEB0301A1FF972FF).zfill(16)

        self._run_test(key, plaintext, expected_ciphertext, expected_100_times)


    def test_vec_7(self):
        key                 = Bytes(0x00000000000000000000000000000000).zfill(16)
        plaintext           = Bytes(0x10000000000000000000000000000000).zfill(16)
        expected_ciphertext = Bytes(0x5DBE1EAC9F7080A88DBED7F6DA101448).zfill(16)
        expected_100_times  = Bytes(0x4A2C157328480659E2931B009B26A72D).zfill(16)

        self._run_test(key, plaintext, expected_ciphertext, expected_100_times)


    # https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/camellia/Camellia-192-128.verified.test-vectors
    def test_vec_8(self):
        key                 = Bytes(0x800000000000000000000000000000000000000000000000).zfill(24)
        plaintext           = Bytes(0x00000000000000000000000000000000).zfill(16)
        expected_ciphertext = Bytes(0x1B6220D365C2176C1D41A5826520FCA1).zfill(16)
        expected_100_times  = Bytes(0xB3697E31ED3BBCEE279682C24921A42B).zfill(16)

        self._run_test(key, plaintext, expected_ciphertext, expected_100_times)


    def test_vec_9(self):
        key                 = Bytes(0x400000000000000000000000000000000000000000000000).zfill(24)
        plaintext           = Bytes(0x00000000000000000000000000000000).zfill(16)
        expected_ciphertext = Bytes(0x0F6DAEEA95CFC8925F23AFA932DF489B).zfill(16)
        expected_100_times  = Bytes(0x02DDF77AAC79196D991C3B7F95D4691A).zfill(16)

        self._run_test(key, plaintext, expected_ciphertext, expected_100_times)


    def test_vec_10(self):
        key                 = Bytes(0x200000000000000000000000000000000000000000000000).zfill(24)
        plaintext           = Bytes(0x00000000000000000000000000000000).zfill(16)
        expected_ciphertext = Bytes(0x7330199225AD384F8DD39582D61389BB).zfill(16)
        expected_100_times  = Bytes(0xE82D72E8A305C004C91B813634840B35).zfill(16)

        self._run_test(key, plaintext, expected_ciphertext, expected_100_times)


    def test_vec_11(self):
        key                 = Bytes(0x100000000000000000000000000000000000000000000000).zfill(24)
        plaintext           = Bytes(0x00000000000000000000000000000000).zfill(16)
        expected_ciphertext = Bytes(0x2CC5A47D5C62F70634E27BA332D37D53).zfill(16)
        expected_100_times  = Bytes(0xF7A212BB06703C055C1BAEAD8EBA7135).zfill(16)

        self._run_test(key, plaintext, expected_ciphertext, expected_100_times)


    def test_vec_12(self):
        key                 = Bytes(0x000000000000000000000000000000000000000000000000).zfill(24)
        plaintext           = Bytes(0x80000000000000000000000000000000).zfill(16)
        expected_ciphertext = Bytes(0x3EB6CC5618EFC98455B5992050D474E7).zfill(16)
        expected_100_times  = Bytes(0xE0054A4E717E07FE41DD6489C252EEC9).zfill(16)

        self._run_test(key, plaintext, expected_ciphertext, expected_100_times)


    def test_vec_13(self):
        key                 = Bytes(0x000000000000000000000000000000000000000000000000).zfill(24)
        plaintext           = Bytes(0x40000000000000000000000000000000).zfill(16)
        expected_ciphertext = Bytes(0xA2C645044CBC74DE5A4A161C6B2E98B9).zfill(16)
        expected_100_times  = Bytes(0x152FFF531FACA2A3DE639099B6D29E92).zfill(16)

        self._run_test(key, plaintext, expected_ciphertext, expected_100_times)


    def test_vec_14(self):
        key                 = Bytes(0x000000000000000000000000000000000000000000000000).zfill(24)
        plaintext           = Bytes(0x20000000000000000000000000000000).zfill(16)
        expected_ciphertext = Bytes(0x36A9A8C164BD90D4972AB1BE56C96A0B).zfill(16)
        expected_100_times  = Bytes(0xEBDA4FFEC6C1FD316EF89633C597905F).zfill(16)

        self._run_test(key, plaintext, expected_ciphertext, expected_100_times)


    def test_vec_15(self):
        key                 = Bytes(0x000000000000000000000000000000000000000000000000).zfill(24)
        plaintext           = Bytes(0x10000000000000000000000000000000).zfill(16)
        expected_ciphertext = Bytes(0x38965592D728F9B765140C0A36A1BCCD).zfill(16)
        expected_100_times  = Bytes(0xFE9679C6166602F36722C6CE3003A5F7).zfill(16)

        self._run_test(key, plaintext, expected_ciphertext, expected_100_times)


    # https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/camellia/Camellia-256-128.verified.test-vectors
    def test_vec_16(self):
        key                 = Bytes(0x8000000000000000000000000000000000000000000000000000000000000000).zfill(32)
        plaintext           = Bytes(0x00000000000000000000000000000000).zfill(16)
        expected_ciphertext = Bytes(0x2136FABDA091DFB5171B94B8EFBB5D08).zfill(16)
        expected_100_times  = Bytes(0x6187E967EEBF74FF17E158C8FD9FDF25).zfill(16)

        self._run_test(key, plaintext, expected_ciphertext, expected_100_times)


    def test_vec_17(self):
        key                 = Bytes(0x4000000000000000000000000000000000000000000000000000000000000000).zfill(32)
        plaintext           = Bytes(0x00000000000000000000000000000000).zfill(16)
        expected_ciphertext = Bytes(0x6EBC4F33B3EADA5DBF25130F3D02CD34).zfill(16)
        expected_100_times  = Bytes(0x1D32AEEAAE22464380CB3A8D19E1CBF6).zfill(16)

        self._run_test(key, plaintext, expected_ciphertext, expected_100_times)


    def test_vec_18(self):
        key                 = Bytes(0x2000000000000000000000000000000000000000000000000000000000000000).zfill(32)
        plaintext           = Bytes(0x00000000000000000000000000000000).zfill(16)
        expected_ciphertext = Bytes(0x3A7BCDC53A1F02EF20C79CFCE107D38B).zfill(16)
        expected_100_times  = Bytes(0xE3A9C01275E0502FD50DF34B86FC59BC).zfill(16)

        self._run_test(key, plaintext, expected_ciphertext, expected_100_times)


    def test_vec_19(self):
        key                 = Bytes(0x1000000000000000000000000000000000000000000000000000000000000000).zfill(32)
        plaintext           = Bytes(0x00000000000000000000000000000000).zfill(16)
        expected_ciphertext = Bytes(0x88A96052B61C5A621EE9A6316A42ED4A).zfill(16)
        expected_100_times  = Bytes(0xEC8A99C3F0D3E6C63C80962CFE3E84DA).zfill(16)

        self._run_test(key, plaintext, expected_ciphertext, expected_100_times)


    def test_vec_20(self):
        key                 = Bytes(0x0000000000000000000000000000000000000000000000000000000000000000).zfill(32)
        plaintext           = Bytes(0x80000000000000000000000000000000).zfill(16)
        expected_ciphertext = Bytes(0xB0C6B88AEA518AB09E847248E91B1B9D).zfill(16)
        expected_100_times  = Bytes(0xB4A2DADB0315ACA6D91564B3F44A1D50).zfill(16)

        self._run_test(key, plaintext, expected_ciphertext, expected_100_times)


    def test_vec_21(self):
        key                 = Bytes(0x0000000000000000000000000000000000000000000000000000000000000000).zfill(32)
        plaintext           = Bytes(0x40000000000000000000000000000000).zfill(16)
        expected_ciphertext = Bytes(0xB8D7684E35FA1DB15BDCEE7A48659858).zfill(16)
        expected_100_times  = Bytes(0x8058A5336D13511E4DB656928C4E0798).zfill(16)

        self._run_test(key, plaintext, expected_ciphertext, expected_100_times)


    def test_vec_22(self):
        key                 = Bytes(0x0000000000000000000000000000000000000000000000000000000000000000).zfill(32)
        plaintext           = Bytes(0x20000000000000000000000000000000).zfill(16)
        expected_ciphertext = Bytes(0xF0CAD59AF92FBB79F36951E697492750).zfill(16)
        expected_100_times  = Bytes(0x1C0CDD48F951FE8FCA31382EF05231F4).zfill(16)

        self._run_test(key, plaintext, expected_ciphertext, expected_100_times)


    def test_vec_23(self):
        key                 = Bytes(0x0000000000000000000000000000000000000000000000000000000000000000).zfill(32)
        plaintext           = Bytes(0x10000000000000000000000000000000).zfill(16)
        expected_ciphertext = Bytes(0x117100F6635389560DC4A2DA24EBA70F).zfill(16)
        expected_100_times  = Bytes(0x3570B1C80824895C13D0A8C6B696E6EF).zfill(16)

        self._run_test(key, plaintext, expected_ciphertext, expected_100_times)
