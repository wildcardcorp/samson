from samson.stream_ciphers.chacha import ChaCha
import codecs
import unittest

# https://tools.ietf.org/html/rfc7539#section-2.3.2
class ChaChaTestCase(unittest.TestCase):
    def _run_test(self, key, nonce, start_ctr, end_ctr, test_vector):
        chacha = ChaCha(key, nonce, 20)
        chunks = list(chacha.yield_state(start_ctr, end_ctr))

        self.assertEqual(chunks[-1], test_vector)


    # https://tools.ietf.org/html/rfc7539#section-2.3.2
    def test_vec1(self):
        key = codecs.decode('00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f'.replace(':', ""), 'hex_codec')
        nonce = codecs.decode('00:00:00:09:00:00:00:4a:00:00:00:00'.replace(':', ""), 'hex_codec')
        test_vector = codecs.decode('10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c 4ed2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e'.replace(" ", ""), 'hex_codec')

        self._run_test(key, nonce, 0, 2, test_vector)


    # https://tools.ietf.org/html/rfc7539#appendix-A
    def test_vect2(self):
        key = codecs.decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex_codec')
        nonce = codecs.decode('000000000000000000000000', 'hex_codec')
        test_vector = codecs.decode('76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586', 'hex_codec')

        self._run_test(key, nonce, 0, 1, test_vector)


    def test_vect3(self):
        key = codecs.decode('0000000000000000000000000000000000000000000000000000000000000001', 'hex_codec')
        nonce = codecs.decode('000000000000000000000000', 'hex_codec')
        test_vector = codecs.decode('4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275ae546963', 'hex_codec')

        self._run_test(key, nonce, 0, 1, test_vector)


    def test_vect4(self):
        key = codecs.decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex_codec')
        nonce = codecs.decode('000000000000000000000000', 'hex_codec')
        test_vector = codecs.decode(b'9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f', 'hex_codec')

        self._run_test(key, nonce, 0, 2, test_vector)


    def test_vect5(self):
        key = codecs.decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex_codec')
        nonce = codecs.decode('000000000000000000000002', 'hex_codec')
        test_vector = codecs.decode(b'c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c78a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d', 'hex_codec')

        self._run_test(key, nonce, 0, 1, test_vector)
