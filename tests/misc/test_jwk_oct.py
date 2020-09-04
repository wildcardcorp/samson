from samson.encoding.jwk.jwk_oct_key import JWKOctKey
from samson.encoding.general import url_b64_decode
import unittest

class JWKOctKeyTestCase(unittest.TestCase):
    def test(self):
        known_jwk = '{"kty": "oct", "k": "QqzzWH1tYqQO48IDvW7VH7gvJz89Ita7G6APhV-uLMo"}'
        correct_decoding = url_b64_decode(b'QqzzWH1tYqQO48IDvW7VH7gvJz89Ita7G6APhV-uLMo')

        # Decode as string
        decoded = JWKOctKey.decode(known_jwk).key
        self.assertEqual(decoded, correct_decoding)

        # Decode as bytes
        decoded = JWKOctKey.decode(known_jwk.encode('utf-8')).key
        self.assertEqual(decoded, correct_decoding)

        # Encode
        encoded = JWKOctKey(decoded).encode()
        self.assertEqual(encoded, known_jwk.encode('utf-8'))

        # Check function
        self.assertTrue(JWKOctKey.check(known_jwk))
        self.assertTrue(JWKOctKey.check(known_jwk.encode('utf-8')))
        self.assertFalse(JWKOctKey.check(b''))
