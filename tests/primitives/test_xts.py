from samson.block_ciphers.modes.xts import XTS
from samson.block_ciphers.rijndael import Rijndael
from samson.utilities.bytes import Bytes
import unittest

# https://svn.python.org/projects/external/openssl-1.0.2d/test/evptests.txt
class XTSTestCase(unittest.TestCase):
    def _run_test(self, key1, key2, plaintext, tweak, expected_ciphertext):
        rij1 = Rijndael(key1)
        rij2 = Rijndael(key2)
        xts = XTS(rij1.encrypt, rij1.decrypt, rij2.encrypt)

        ciphertext = xts.encrypt(plaintext, tweak)
        self.assertEqual(ciphertext, expected_ciphertext)
        self.assertEqual(xts.decrypt(ciphertext, tweak), plaintext)



    def test_vec0(self):
        key1                = Bytes(0x0).zfill(16)
        key2                = Bytes(0x0).zfill(16)
        plaintext           = Bytes(0x0).zfill(32)
        tweak               = 0
        expected_ciphertext = Bytes(0x917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e)
        self._run_test(key1, key2, plaintext, tweak, expected_ciphertext)



    def test_vec1(self):
        key1                = Bytes(0x11111111111111111111111111111111).zfill(16)
        key2                = Bytes(0x22222222222222222222222222222222).zfill(16)
        plaintext           = Bytes(0x4444444444444444444444444444444444444444444444444444444444444444).zfill(32)
        tweak               = 0x33333333330000000000000000000000
        expected_ciphertext = Bytes(0xc454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0)
        self._run_test(key1, key2, plaintext, tweak, expected_ciphertext)



    def test_vec2(self):
        key1                = Bytes(0xfffefdfcfbfaf9f8f7f6f5f4f3f2f1f0).zfill(16)
        key2                = Bytes(0x22222222222222222222222222222222).zfill(16)
        plaintext           = Bytes(0x4444444444444444444444444444444444444444444444444444444444444444).zfill(32)
        tweak               = 0x33333333330000000000000000000000
        expected_ciphertext = Bytes(0xaf85336b597afc1a900b2eb21ec949d292df4c047e0b21532186a5971a227a89)
        self._run_test(key1, key2, plaintext, tweak, expected_ciphertext)



    def test_vec3(self):
        key1                = Bytes(0x27182818284590452353602874713526).zfill(16)
        key2                = Bytes(0x31415926535897932384626433832795).zfill(16)
        plaintext           = Bytes(0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff).zfill(512)
        tweak               = 0
        expected_ciphertext = Bytes(0x27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89cc78cf7f5e543445f8333d8fa7f56000005279fa5d8b5e4ad40e736ddb4d35412328063fd2aab53e5ea1e0a9f332500a5df9487d07a5c92cc512c8866c7e860ce93fdf166a24912b422976146ae20ce846bb7dc9ba94a767aaef20c0d61ad02655ea92dc4c4e41a8952c651d33174be51a10c421110e6d81588ede82103a252d8a750e8768defffed9122810aaeb99f9172af82b604dc4b8e51bcb08235a6f4341332e4ca60482a4ba1a03b3e65008fc5da76b70bf1690db4eae29c5f1badd03c5ccf2a55d705ddcd86d449511ceb7ec30bf12b1fa35b913f9f747a8afd1b130e94bff94effd01a91735ca1726acd0b197c4e5b03393697e126826fb6bbde8ecc1e08298516e2c9ed03ff3c1b7860f6de76d4cecd94c8119855ef5297ca67e9f3e7ff72b1e99785ca0a7e7720c5b36dc6d72cac9574c8cbbc2f801e23e56fd344b07f22154beba0f08ce8891e643ed995c94d9a69c9f1b5f499027a78572aeebd74d20cc39881c213ee770b1010e4bea718846977ae119f7a023ab58cca0ad752afe656bb3c17256a9f6e9bf19fdd5a38fc82bbe872c5539edb609ef4f79c203ebb140f2e583cb2ad15b4aa5b655016a8449277dbd477ef2c8d6c017db738b18deb4a427d1923ce3ff262735779a418f20a282df920147beabe421ee5319d0568)
        self._run_test(key1, key2, plaintext, tweak, expected_ciphertext)



    def test_vec4(self):
        key1                = Bytes(0x27182818284590452353602874713526).zfill(16)
        key2                = Bytes(0x31415926535897932384626433832795).zfill(16)
        plaintext           = Bytes(0x27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89cc78cf7f5e543445f8333d8fa7f56000005279fa5d8b5e4ad40e736ddb4d35412328063fd2aab53e5ea1e0a9f332500a5df9487d07a5c92cc512c8866c7e860ce93fdf166a24912b422976146ae20ce846bb7dc9ba94a767aaef20c0d61ad02655ea92dc4c4e41a8952c651d33174be51a10c421110e6d81588ede82103a252d8a750e8768defffed9122810aaeb99f9172af82b604dc4b8e51bcb08235a6f4341332e4ca60482a4ba1a03b3e65008fc5da76b70bf1690db4eae29c5f1badd03c5ccf2a55d705ddcd86d449511ceb7ec30bf12b1fa35b913f9f747a8afd1b130e94bff94effd01a91735ca1726acd0b197c4e5b03393697e126826fb6bbde8ecc1e08298516e2c9ed03ff3c1b7860f6de76d4cecd94c8119855ef5297ca67e9f3e7ff72b1e99785ca0a7e7720c5b36dc6d72cac9574c8cbbc2f801e23e56fd344b07f22154beba0f08ce8891e643ed995c94d9a69c9f1b5f499027a78572aeebd74d20cc39881c213ee770b1010e4bea718846977ae119f7a023ab58cca0ad752afe656bb3c17256a9f6e9bf19fdd5a38fc82bbe872c5539edb609ef4f79c203ebb140f2e583cb2ad15b4aa5b655016a8449277dbd477ef2c8d6c017db738b18deb4a427d1923ce3ff262735779a418f20a282df920147beabe421ee5319d0568).zfill(512)
        tweak               = 0x01000000000000000000000000000000
        expected_ciphertext = Bytes(0x264d3ca8512194fec312c8c9891f279fefdd608d0c027b60483a3fa811d65ee59d52d9e40ec5672d81532b38b6b089ce951f0f9c35590b8b978d175213f329bb1c2fd30f2f7f30492a61a532a79f51d36f5e31a7c9a12c286082ff7d2394d18f783e1a8e72c722caaaa52d8f065657d2631fd25bfd8e5baad6e527d763517501c68c5edc3cdd55435c532d7125c8614deed9adaa3acade5888b87bef641c4c994c8091b5bcd387f3963fb5bc37aa922fbfe3df4e5b915e6eb514717bdd2a74079a5073f5c4bfd46adf7d282e7a393a52579d11a028da4d9cd9c77124f9648ee383b1ac763930e7162a8d37f350b2f74b8472cf09902063c6b32e8c2d9290cefbd7346d1c779a0df50edcde4531da07b099c638e83a755944df2aef1aa31752fd323dcb710fb4bfbb9d22b925bc3577e1b8949e729a90bbafeacf7f7879e7b1147e28ba0bae940db795a61b15ecf4df8db07b824bb062802cc98a9545bb2aaeed77cb3fc6db15dcd7d80d7d5bc406c4970a3478ada8899b329198eb61c193fb6275aa8ca340344a75a862aebe92eee1ce032fd950b47d7704a3876923b4ad62844bf4a09c4dbe8b4397184b7471360c9564880aedddb9baa4af2e75394b08cd32ff479c57a07d3eab5d54de5f9738b8d27f27a9f0ab11799d7b7ffefb2704c95c6ad12c39f1e867a4b7b1d7818a4b753dfd2a89ccb45e001a03a867b187f225dd)
        self._run_test(key1, key2, plaintext, tweak, expected_ciphertext)



    def test_vec5(self):
        key1                = Bytes(0x27182818284590452353602874713526).zfill(16)
        key2                = Bytes(0x31415926535897932384626433832795).zfill(16)
        plaintext           = Bytes(0x27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89cc78cf7f5e543445f8333d8fa7f56000005279fa5d8b5e4ad40e736ddb4d35412328063fd2aab53e5ea1e0a9f332500a5df9487d07a5c92cc512c8866c7e860ce93fdf166a24912b422976146ae20ce846bb7dc9ba94a767aaef20c0d61ad02655ea92dc4c4e41a8952c651d33174be51a10c421110e6d81588ede82103a252d8a750e8768defffed9122810aaeb99f9172af82b604dc4b8e51bcb08235a6f4341332e4ca60482a4ba1a03b3e65008fc5da76b70bf1690db4eae29c5f1badd03c5ccf2a55d705ddcd86d449511ceb7ec30bf12b1fa35b913f9f747a8afd1b130e94bff94effd01a91735ca1726acd0b197c4e5b03393697e126826fb6bbde8ecc1e08298516e2c9ed03ff3c1b7860f6de76d4cecd94c8119855ef5297ca67e9f3e7ff72b1e99785ca0a7e7720c5b36dc6d72cac9574c8cbbc2f801e23e56fd344b07f22154beba0f08ce8891e643ed995c94d9a69c9f1b5f499027a78572aeebd74d20cc39881c213ee770b1010e4bea718846977ae119f7a023ab58cca0ad752afe656bb3c17256a9f6e9bf19fdd5a38fc82bbe872c5539edb609ef4f79c203ebb140f2e583cb2ad15b4aa5b655016a8449277dbd477ef2c8d6c017db738b18deb4a427d1923ce3ff262735779a418f20a282df920147beabe421ee5319d0568).zfill(512)
        tweak               = 0x01000000000000000000000000000000
        expected_ciphertext = Bytes(0x264d3ca8512194fec312c8c9891f279fefdd608d0c027b60483a3fa811d65ee59d52d9e40ec5672d81532b38b6b089ce951f0f9c35590b8b978d175213f329bb1c2fd30f2f7f30492a61a532a79f51d36f5e31a7c9a12c286082ff7d2394d18f783e1a8e72c722caaaa52d8f065657d2631fd25bfd8e5baad6e527d763517501c68c5edc3cdd55435c532d7125c8614deed9adaa3acade5888b87bef641c4c994c8091b5bcd387f3963fb5bc37aa922fbfe3df4e5b915e6eb514717bdd2a74079a5073f5c4bfd46adf7d282e7a393a52579d11a028da4d9cd9c77124f9648ee383b1ac763930e7162a8d37f350b2f74b8472cf09902063c6b32e8c2d9290cefbd7346d1c779a0df50edcde4531da07b099c638e83a755944df2aef1aa31752fd323dcb710fb4bfbb9d22b925bc3577e1b8949e729a90bbafeacf7f7879e7b1147e28ba0bae940db795a61b15ecf4df8db07b824bb062802cc98a9545bb2aaeed77cb3fc6db15dcd7d80d7d5bc406c4970a3478ada8899b329198eb61c193fb6275aa8ca340344a75a862aebe92eee1ce032fd950b47d7704a3876923b4ad62844bf4a09c4dbe8b4397184b7471360c9564880aedddb9baa4af2e75394b08cd32ff479c57a07d3eab5d54de5f9738b8d27f27a9f0ab11799d7b7ffefb2704c95c6ad12c39f1e867a4b7b1d7818a4b753dfd2a89ccb45e001a03a867b187f225dd)
        self._run_test(key1, key2, plaintext, tweak, expected_ciphertext)



    def test_vec6(self):
        key1                = Bytes(0x27182818284590452353602874713526).zfill(16)
        key2                = Bytes(0x31415926535897932384626433832795).zfill(16)
        plaintext           = Bytes(0x264d3ca8512194fec312c8c9891f279fefdd608d0c027b60483a3fa811d65ee59d52d9e40ec5672d81532b38b6b089ce951f0f9c35590b8b978d175213f329bb1c2fd30f2f7f30492a61a532a79f51d36f5e31a7c9a12c286082ff7d2394d18f783e1a8e72c722caaaa52d8f065657d2631fd25bfd8e5baad6e527d763517501c68c5edc3cdd55435c532d7125c8614deed9adaa3acade5888b87bef641c4c994c8091b5bcd387f3963fb5bc37aa922fbfe3df4e5b915e6eb514717bdd2a74079a5073f5c4bfd46adf7d282e7a393a52579d11a028da4d9cd9c77124f9648ee383b1ac763930e7162a8d37f350b2f74b8472cf09902063c6b32e8c2d9290cefbd7346d1c779a0df50edcde4531da07b099c638e83a755944df2aef1aa31752fd323dcb710fb4bfbb9d22b925bc3577e1b8949e729a90bbafeacf7f7879e7b1147e28ba0bae940db795a61b15ecf4df8db07b824bb062802cc98a9545bb2aaeed77cb3fc6db15dcd7d80d7d5bc406c4970a3478ada8899b329198eb61c193fb6275aa8ca340344a75a862aebe92eee1ce032fd950b47d7704a3876923b4ad62844bf4a09c4dbe8b4397184b7471360c9564880aedddb9baa4af2e75394b08cd32ff479c57a07d3eab5d54de5f9738b8d27f27a9f0ab11799d7b7ffefb2704c95c6ad12c39f1e867a4b7b1d7818a4b753dfd2a89ccb45e001a03a867b187f225dd).zfill(512)
        tweak               = 0x02000000000000000000000000000000
        expected_ciphertext = Bytes(0xfa762a3680b76007928ed4a4f49a9456031b704782e65e16cecb54ed7d017b5e18abd67b338e81078f21edb7868d901ebe9c731a7c18b5e6dec1d6a72e078ac9a4262f860beefa14f4e821018272e411a951502b6e79066e84252c3346f3aa62344351a291d4bedc7a07618bdea2af63145cc7a4b8d4070691ae890cd65733e7946e9021a1dffc4c59f159425ee6d50ca9b135fa6162cea18a939838dc000fb386fad086acce5ac07cb2ece7fd580b00cfa5e98589631dc25e8e2a3daf2ffdec26531659912c9d8f7a15e5865ea8fb5816d6207052bd7128cd743c12c8118791a4736811935eb982a532349e31dd401e0b660a568cb1a4711f552f55ded59f1f15bf7196b3ca12a91e488ef59d64f3a02bf45239499ac6176ae321c4a211ec545365971c5d3f4f09d4eb139bfdf2073d33180b21002b65cc9865e76cb24cd92c874c24c18350399a936ab3637079295d76c417776b94efce3a0ef7206b15110519655c956cbd8b2489405ee2b09a6b6eebe0c53790a12a8998378b33a5b71159625f4ba49d2a2fdba59fbf0897bc7aabd8d707dc140a80f0f309f835d3da54ab584e501dfa0ee977fec543f74186a802b9a37adb3e8291eca04d66520d229e60401e7282bef486ae059aa70696e0e305d777140a7a883ecdcb69b9ff938e8a4231864c69ca2c2043bed007ff3e605e014bcf518138dc3a25c5e236171a2d01d6)
        self._run_test(key1, key2, plaintext, tweak, expected_ciphertext)



    def test_vec7(self):
        key1                = Bytes(0x2718281828459045235360287471352662497757247093699959574966967627).zfill(32)
        key2                = Bytes(0x3141592653589793238462643383279502884197169399375105820974944592).zfill(32)
        plaintext           = Bytes(0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff).zfill(512)
        tweak               = 0xff000000000000000000000000000000
        expected_ciphertext = Bytes(0x1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b5d31e276f8fe4a8d66b317f9ac683f44680a86ac35adfc3345befecb4bb188fd5776926c49a3095eb108fd1098baec70aaa66999a72a82f27d848b21d4a741b0c5cd4d5fff9dac89aeba122961d03a757123e9870f8acf1000020887891429ca2a3e7a7d7df7b10355165c8b9a6d0a7de8b062c4500dc4cd120c0f7418dae3d0b5781c34803fa75421c790dfe1de1834f280d7667b327f6c8cd7557e12ac3a0f93ec05c52e0493ef31a12d3d9260f79a289d6a379bc70c50841473d1a8cc81ec583e9645e07b8d9670655ba5bbcfecc6dc3966380ad8fecb17b6ba02469a020a84e18e8f84252070c13e9f1f289be54fbc481457778f616015e1327a02b140f1505eb309326d68378f8374595c849d84f4c333ec4423885143cb47bd71c5edae9be69a2ffeceb1bec9de244fbe15992b11b77c040f12bd8f6a975a44a0f90c29a9abc3d4d893927284c58754cce294529f8614dcd2aba991925fedc4ae74ffac6e333b93eb4aff0479da9a410e4450e0dd7ae4c6e2910900575da401fc07059f645e8b7e9bfdef33943054ff84011493c27b3429eaedb4ed5376441a77ed43851ad77f16f541dfd269d50d6a5f14fb0aab1cbb4c1550be97f7ab4066193c4caa773dad38014bd2092fa755c824bb5e54c4f36ffda9fcea70b9c6e693e148c151)
        self._run_test(key1, key2, plaintext, tweak, expected_ciphertext)



    def test_vec8(self):
        key1                = Bytes(0x2718281828459045235360287471352662497757247093699959574966967627).zfill(32)
        key2                = Bytes(0x3141592653589793238462643383279502884197169399375105820974944592).zfill(32)
        plaintext           = Bytes(0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff).zfill(512)
        tweak               = 0xffff0000000000000000000000000000
        expected_ciphertext = Bytes(0x77a31251618a15e6b92d1d66dffe7b50b50bad552305ba0217a610688eff7e11e1d0225438e093242d6db274fde801d4cae06f2092c728b2478559df58e837c2469ee4a4fa794e4bbc7f39bc026e3cb72c33b0888f25b4acf56a2a9804f1ce6d3d6e1dc6ca181d4b546179d55544aa7760c40d06741539c7e3cd9d2f6650b2013fd0eeb8c2b8e3d8d240ccae2d4c98320a7442e1c8d75a42d6e6cfa4c2eca1798d158c7aecdf82490f24bb9b38e108bcda12c3faf9a21141c3613b58367f922aaa26cd22f23d708dae699ad7cb40a8ad0b6e2784973dcb605684c08b8d6998c69aac049921871ebb65301a4619ca80ecb485a31d744223ce8ddc2394828d6a80470c092f5ba413c3378fa6054255c6f9df4495862bbb3287681f931b687c888abf844dfc8fc28331e579928cd12bd2390ae123cf03818d14dedde5c0c24c8ab018bfca75ca096f2d531f3d1619e785f1ada437cab92e980558b3dce1474afb75bfedbf8ff54cb2618e0244c9ac0d3c66fb51598cd2db11f9be39791abe447c63094f7c453b7ff87cb5bb36b7c79efb0872d17058b83b15ab0866ad8a58656c5a7e20dbdf308b2461d97c0ec0024a2715055249cf3b478ddd4740de654f75ca686e0d7345c69ed50cdc2a8b332b1f8824108ac937eb050585608ee734097fc09054fbff89eeaeea791f4a7ab1f9868294a4f9e27b42af8100cb9d59cef9645803)
        self._run_test(key1, key2, plaintext, tweak, expected_ciphertext)



    def test_vec9(self):
        key1                = Bytes(0x2718281828459045235360287471352662497757247093699959574966967627).zfill(32)
        key2                = Bytes(0x3141592653589793238462643383279502884197169399375105820974944592).zfill(32)
        plaintext           = Bytes(0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff).zfill(512)
        tweak               = 0xffffff00000000000000000000000000
        expected_ciphertext = Bytes(0xe387aaa58ba483afa7e8eb469778317ecf4cf573aa9d4eac23f2cdf914e4e200a8b490e42ee646802dc6ee2b471b278195d60918ececb44bf79966f83faba0499298ebc699c0c8634715a320bb4f075d622e74c8c932004f25b41e361025b5a87815391f6108fc4afa6a05d9303c6ba68a128a55705d415985832fdeaae6c8e19110e84d1b1f199a2692119edc96132658f09da7c623efcec712537a3d94c0bf5d7e352ec94ae5797fdb377dc1551150721adf15bd26a8efc2fcaad56881fa9e62462c28f30ae1ceaca93c345cf243b73f542e2074a705bd2643bb9f7cc79bb6e7091ea6e232df0f9ad0d6cf502327876d82207abf2115cdacf6d5a48f6c1879a65b115f0f8b3cb3c59d15dd8c769bc014795a1837f3901b5845eb491adfefe097b1fa30a12fc1f65ba22905031539971a10f2f36c321bb51331cdefb39e3964c7ef079994f5b69b2edd83a71ef549971ee93f44eac3938fcdd61d01fa71799da3a8091c4c48aa9ed263ff0749df95d44fef6a0bb578ec69456aa5408ae32c7af08ad7ba8921287e3bbee31b767be06a0e705c864a769137df28292283ea81a2480241b44d9921cdbec1bc28dc1fda114bd8e5217ac9d8ebafa720e9da4f9ace231cc949e5b96fe76ffc21063fddc83a6b8679c00d35e09576a875305bed5f36ed242c8900dd1fa965bc950dfce09b132263a1eef52dd6888c309f5a7d712826)
        self._run_test(key1, key2, plaintext, tweak, expected_ciphertext)



    def test_vec10(self):
        key1                = Bytes(0x2718281828459045235360287471352662497757247093699959574966967627).zfill(32)
        key2                = Bytes(0x3141592653589793238462643383279502884197169399375105820974944592).zfill(32)
        plaintext           = Bytes(0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff).zfill(512)
        tweak               = 0xffffffff000000000000000000000000
        expected_ciphertext = Bytes(0xbf53d2dade78e822a4d949a9bc6766b01b06a8ef70d26748c6a7fc36d80ae4c5520f7c4ab0ac8544424fa405162fef5a6b7f229498063618d39f0003cb5fb8d1c86b643497da1ff945c8d3bedeca4f479702a7a735f043ddb1d6aaade3c4a0ac7ca7f3fa5279bef56f82cd7a2f38672e824814e10700300a055e1630b8f1cb0e919f5e942010a416e2bf48cb46993d3cb6a51c19bacf864785a00bc2ecff15d350875b246ed53e68be6f55bd7e05cfc2b2ed6432198a6444b6d8c247fab941f569768b5c429366f1d3f00f0345b96123d56204c01c63b22ce78baf116e525ed90fdea39fa469494d3866c31e05f295ff21fea8d4e6e13d67e47ce722e9698a1c1048d68ebcde76b86fcf976eab8aa9790268b7068e017a8b9b749409514f1053027fd16c3786ea1bac5f15cb79711ee2abe82f5cf8b13ae73030ef5b9e4457e75d1304f988d62dd6fc4b94ed38ba831da4b7634971b6cd8ec325d9c61c00f1df73627ed3745a5e8489f3a95c69639c32cd6e1d537a85f75cc844726e8a72fc0077ad22000f1d5078f6b866318c668f1ad03d5a5fced5219f2eabbd0aa5c0f460d183f04404a0d6f469558e81fab24a167905ab4c7878502ad3e38fdbe62a41556cec37325759533ce8f25f367c87bb5578d667ae93f9e2fd99bcbc5f2fbba88cf6516139420fcff3b7361d86322c4bd84c82f335abb152c4a93411373aaa8220)
        self._run_test(key1, key2, plaintext, tweak, expected_ciphertext)



    def test_vec11(self):
        key1                = Bytes(0xfffefdfcfbfaf9f8f7f6f5f4f3f2f1f0).zfill(16)
        key2                = Bytes(0xbfbebdbcbbbab9b8b7b6b5b4b3b2b1b0).zfill(16)
        plaintext           = Bytes(0x000102030405060708090a0b0c0d0e0f10).zfill(17)
        tweak               = 0x9a785634120000000000000000000000
        expected_ciphertext = Bytes(0x6c1625db4671522d3d7599601de7ca09ed)
        self._run_test(key1, key2, plaintext, tweak, expected_ciphertext)



    def test_vec12(self):
        key1                = Bytes(0xfffefdfcfbfaf9f8f7f6f5f4f3f2f1f0).zfill(16)
        key2                = Bytes(0xbfbebdbcbbbab9b8b7b6b5b4b3b2b1b0).zfill(16)
        plaintext           = Bytes(0x000102030405060708090a0b0c0d0e0f1011).zfill(18)
        tweak               = 0x9a785634120000000000000000000000
        expected_ciphertext = Bytes(0xd069444b7a7e0cab09e24447d24deb1fedbf)
        self._run_test(key1, key2, plaintext, tweak, expected_ciphertext)



    def test_vec13(self):
        key1                = Bytes(0xfffefdfcfbfaf9f8f7f6f5f4f3f2f1f0).zfill(16)
        key2                = Bytes(0xbfbebdbcbbbab9b8b7b6b5b4b3b2b1b0).zfill(16)
        plaintext           = Bytes(0x000102030405060708090a0b0c0d0e0f101112).zfill(19)
        tweak               = 0x9a785634120000000000000000000000
        expected_ciphertext = Bytes(0xe5df1351c0544ba1350b3363cd8ef4beedbf9d)
        self._run_test(key1, key2, plaintext, tweak, expected_ciphertext)



    def test_vec14(self):
        key1                = Bytes(0xfffefdfcfbfaf9f8f7f6f5f4f3f2f1f0).zfill(16)
        key2                = Bytes(0xbfbebdbcbbbab9b8b7b6b5b4b3b2b1b0).zfill(16)
        plaintext           = Bytes(0x000102030405060708090a0b0c0d0e0f10111213).zfill(20)
        tweak               = 0x9a785634120000000000000000000000
        expected_ciphertext = Bytes(0x9d84c813f719aa2c7be3f66171c7c5c2edbf9dac)
        self._run_test(key1, key2, plaintext, tweak, expected_ciphertext)



    def test_vec15(self):
        key1                = Bytes(0xe0e1e2e3e4e5e6e7e8e9eaebecedeeef).zfill(16)
        key2                = Bytes(0xc0c1c2c3c4c5c6c7c8c9cacbcccdcecf).zfill(16)
        plaintext           = Bytes(0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff).zfill(512)
        tweak               = 0x21436587a90000000000000000000000
        expected_ciphertext = Bytes(0x38b45812ef43a05bd957e545907e223b954ab4aaf088303ad910eadf14b42be68b2461149d8c8ba85f992be970bc621f1b06573f63e867bf5875acafa04e42ccbd7bd3c2a0fb1fff791ec5ec36c66ae4ac1e806d81fbf709dbe29e471fad38549c8e66f5345d7c1eb94f405d1ec785cc6f6a68f6254dd8339f9d84057e01a17741990482999516b5611a38f41bb6478e6f173f320805dd71b1932fc333cb9ee39936beea9ad96fa10fb4112b901734ddad40bc1878995f8e11aee7d141a2f5d48b7a4e1e7f0b2c04830e69a4fd1378411c2f287edf48c6c4e5c247a19680f7fe41cefbd49b582106e3616cbbe4dfb2344b2ae9519391f3e0fb4922254b1d6d2d19c6d4d537b3a26f3bcc51588b32f3eca0829b6a5ac72578fb814fb43cf80d64a233e3f997a3f02683342f2b33d25b492536b93becb2f5e1a8b82f5b883342729e8ae09d16938841a21a97fb543eea3bbff59f13c1a18449e398701c1ad51648346cbc04c27bb2da3b93a1372ccae548fb53bee476f9e9c91773b1bb19828394d55d3e1a20ed69113a860b6829ffa847224604435070221b257e8dff783615d2cae4803a93aa4334ab482a0afac9c0aeda70b45a481df5dec5df8cc0f423c77a5fd46cd312021d4b438862419a791be03bb4d97c0e59578542531ba466a83baf92cefc151b5cc1611a167893819b63fb8a6b18e86de60290fa72b797b0ce59f3)
        self._run_test(key1, key2, plaintext, tweak, expected_ciphertext)
