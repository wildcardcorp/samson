from samson.encoding.jwt import JWT
from samson.encoding.jwa import JWA
from samson.public_key.rsa import RSA
from samson.utilities.bytes import Bytes
import unittest

BODY = {
    "sub": "1234567890",
    "name": "John Doe",
    "iat": 1516239022
}

HS256_TESTS = [
    (b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', b'your-256-bit-secret'),
    (b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRGVlciIsImlhdCI6MTUxNjIzOTAyMn0.blSEY3tWnWPQW41-zng0dXM0jLjVZ5bqzftwqyw1-KY', b'a bunch of text'),
    (b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImhpeWEifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRGVlciIsImlhdCI6MTUxNjIzOTAyMn0.4JvNuOzOV5a-RCt5Xhsdh03nWD9N82cd__gRwq8TD3w', b'another key')
]

# Tests generated from https://jwt.io/
class JWTTestCase(unittest.TestCase):
    def _run_tests(self, test_suite):
        for token, key in test_suite:
            print(token, key)
            jwt = JWT.parse(token)
            print(jwt)
            print(jwt.encode())
            self.assertTrue(jwt.verify(key))
    

    def test_hs256(self):
        self._run_tests(HS256_TESTS)




    # def test_gauntlet(self):
    #     for jwa in [JWA.HS256, JWA.HS384, JWA.HS512, JWA.ES256, JWA.ES384, JWA.ES512]:
    #         for _ in range(50):
    #             key = Bytes.random(16)
    #             jwt = JWT.create(jwa, BODY, key)

    #             self.assertTrue(jwt.verify(key))
        
    #     for jwa in [JWA.RS256, JWA.RS384, JWA.RS512]:
    #         for _ in range(10):
    #             key = RSA(2048)
    #             jwt = JWT.create(jwa, BODY, key)

    #             self.assertTrue(jwt.verify(key))