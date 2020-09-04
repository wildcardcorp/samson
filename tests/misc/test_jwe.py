from samson.protocols.jwt.jwa import JWAContentEncryptionAlg, JWAKeyEncryptionAlg, JWA_ALG_MAP
from samson.protocols.jwt.jwe import JWE, JWESet
from samson.protocols.ecdhe import ECDHE
from samson.protocols.dh25519 import DH25519
from samson.public_key.rsa import RSA
from samson.public_key.ecdsa import ECDSA

# Have to import because PKIAutoParser can't see the subclass otherwise
from samson.encoding.general import PKIAutoParser
from samson.encoding.jwk.jwk_oct_key import JWKOctKey
from samson.utilities.bytes import Bytes
from samson.math.algebra.curves.named import P256, P384, P521, Curve25519, Curve448
import unittest


# Key generation functions

def sym_byte_key(length):
    key = Bytes.random(length)
    return key, key


def gen_rsa_key():
    rsa = RSA(2048)
    return rsa, rsa


def gen_ec_key(curve):
    dh_a = ECDHE(G=curve.G)
    dh_b = ECDHE(G=curve.G)
    return (dh_a, dh_b.pub), dh_b


def gen_ed_key(curve):
    dh_a = DH25519(curve=curve)
    dh_b = DH25519(curve=curve)
    return (dh_a, dh_b.pub), dh_b


class JWETestCase(unittest.TestCase):
    # https://tools.ietf.org/html/rfc7518#appendix-B.1
    def _run_acbc_hs_test(self, enc_alg, K, P, IV, A, E, T):
        enc = JWA_ALG_MAP[enc_alg]
        ciphertext, auth_tag = enc.encrypt_and_auth(K, IV, P, A)

        self.assertEqual(ciphertext, E)
        self.assertEqual(auth_tag, T)
        self.assertEqual(enc.decrypt(K, IV, E, A, auth_tag), P)


    def test_a128_cbc_hs256(self):
        K  = Bytes(0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f).zfill(32)
        P  = Bytes(0x41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d7573742062652061626c6520746f2066616c6c20696e746f207468652068616e6473206f662074686520656e656d7920776974686f757420696e636f6e76656e69656e6365)
        IV = Bytes(0x1af38c2dc2b96ffdd86694092341bc04)
        A  = Bytes(0x546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673)

        E  = Bytes(0xc80edfa32ddf39d5ef00c0b468834279a2e46a1b8049f792f76bfe54b903a9c9a94ac9b47ad2655c5f10f9aef71427e2fc6f9b3f399a221489f16362c703233609d45ac69864e3321cf82935ac4096c86e133314c54019e8ca7980dfa4b9cf1b384c486f3a54c51078158ee5d79de59fbd34d848b3d69550a67646344427ade54b8851ffb598f7f80074b9473c82e2db)
        T  = Bytes(0x652c3fa36b0a7c5b3219fab3a30bc1c4)
        self._run_acbc_hs_test(JWAContentEncryptionAlg.A128CBC_HS256, K, P, IV, A, E, T)


    def test_a192_cbc_hs384(self):
        K  = Bytes(0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f).zfill(48)
        P  = Bytes(0x41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d7573742062652061626c6520746f2066616c6c20696e746f207468652068616e6473206f662074686520656e656d7920776974686f757420696e636f6e76656e69656e6365)
        IV = Bytes(0x1af38c2dc2b96ffdd86694092341bc04)
        A  = Bytes(0x546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673)

        E  = Bytes(0xea65da6b59e61edb419be62d19712ae5d303eeb50052d0dfd6697f77224c8edb000d279bdc14c1072654bd30944230c657bed4ca0c9f4a8466f22b226d1746214bf8cfc2400add9f5126e479663fc90b3bed787a2f0ffcbf3904be2a641d5c2105bfe591bae23b1d7449e532eef60a9ac8bb6c6b01d35d49787bcd57ef484927f280adc91ac0c4e79c7b11efc60054e3)
        T  = Bytes(0x8490ac0e58949bfe51875d733f93ac2075168039ccc733d7)
        self._run_acbc_hs_test(JWAContentEncryptionAlg.A192CBC_HS384, K, P, IV, A, E, T)


    def test_a256_cbc_hs512(self):
        K  = Bytes(0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f).zfill(64)
        P  = Bytes(0x41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d7573742062652061626c6520746f2066616c6c20696e746f207468652068616e6473206f662074686520656e656d7920776974686f757420696e636f6e76656e69656e6365)
        IV = Bytes(0x1af38c2dc2b96ffdd86694092341bc04)
        A  = Bytes(0x546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673)

        E  = Bytes(0x4affaaadb78c31c5da4b1b590d10ffbd3dd8d5d302423526912da037ecbcc7bd822c301dd67c373bccb584ad3e9279c2e6d12a1374b77f077553df829410446b36ebd97066296ae6427ea75c2e0846a11a09ccf5370dc80bfecbad28c73f09b3a3b75e662a2594410ae496b2e2e6609e31e6e02cc837f053d21f37ff4f51950bbe2638d09dd7a4930930806d0703b1f6)
        T  = Bytes(0x4dd3b4c088a7f45c216839645b2012bf2e6269a8c56a816dbc1b267761955bc5)
        self._run_acbc_hs_test(JWAContentEncryptionAlg.A256CBC_HS512, K, P, IV, A, E, T)


    # https://tools.ietf.org/html/rfc7518#appendix-C
    def test_ecdh_es_derive(self):
        from samson.protocols.jwt.jwa import JWA_ECDH_ES
        from samson.encoding.general import url_b64_decode

        alice_key = b'{"kty":"EC", "crv":"P-256", "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0", "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps", "d":"0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"}'
        bob_key   = b'{"kty":"EC", "crv":"P-256", "x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ", "y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck", "d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}'

        alice_jwk = PKIAutoParser.import_key(alice_key).key
        bob_jwk   = PKIAutoParser.import_key(bob_key).key

        alice_dh = ECDHE(d=alice_jwk.d, G=alice_jwk.G)
        bob_dh   = ECDHE(d=bob_jwk.d, G=bob_jwk.G)

        header = {'apu': 'QWxpY2U', 'apv': 'Qm9i', 'enc': 'A128GCM'}

        alg = JWA_ECDH_ES()
        self.assertEqual(alg.derive((alice_dh, bob_dh.pub), 16, header), url_b64_decode(b'VqqN6vgjbSBcIijNcacQGg'))


    def _run_ecdh_es_edwards_exchange(self, d, curve, bob_jwk, expected_Z):
        from samson.protocols.dh25519 import DH25519
        from samson.encoding.jwk.jwk_eddsa_public_key import JWKEdDSAPublicKey

        alice_dh = DH25519(d=d.int(), curve=curve)
        bob_dh   = JWKEdDSAPublicKey.decode(bob_jwk).key
        Z        = alice_dh.derive_key(bob_dh.pub)

        self.assertEqual(Z, expected_Z)


    # From https://tools.ietf.org/html/rfc8037#appendix-A.6
    def test_ecdh_es_x25519_derive(self):
        d          = Bytes(0x77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a)[::-1]
        curve      = Curve25519
        bob_jwk    = b'{"kty":"OKP","crv":"X25519","kid":"Bob","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}'
        expected_Z = Bytes(0x4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742, 'little')
        self._run_ecdh_es_edwards_exchange(d, curve, bob_jwk, expected_Z)


    # From https://tools.ietf.org/html/rfc8037#appendix-A.7
    def test_ecdh_es_x448_derive(self):
        d          = Bytes(0x9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b)[::-1]
        curve      = Curve448
        bob_jwk    = b'{"kty":"OKP","crv":"X448","kid":"Dave","x":"PreoKbDNIPW8_AtZm2_sz22kYnEHvbDU80W0MCfYuXL8PjT7QjKhPKcG3LV67D2uB73BxnvzNgk"}'
        expected_Z = Bytes(0x07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d, 'little')
        self._run_ecdh_es_edwards_exchange(d, curve, bob_jwk, expected_Z)



    ALG_SPEC = [
        (JWAKeyEncryptionAlg.A128KW, lambda: sym_byte_key(16)),
        (JWAKeyEncryptionAlg.A192KW, lambda: sym_byte_key(24)),
        (JWAKeyEncryptionAlg.A256KW, lambda: sym_byte_key(32)),
        (JWAKeyEncryptionAlg.A128GCMKW, lambda: sym_byte_key(16)),
        (JWAKeyEncryptionAlg.A192GCMKW, lambda: sym_byte_key(24)),
        (JWAKeyEncryptionAlg.A256GCMKW, lambda: sym_byte_key(32)),
        (JWAKeyEncryptionAlg.RSA1_5, lambda: gen_rsa_key()),
        (JWAKeyEncryptionAlg.RSA_OAEP, lambda: gen_rsa_key()),
        (JWAKeyEncryptionAlg.RSA_OAEP_256, lambda: gen_rsa_key()),
        (JWAKeyEncryptionAlg.dir, lambda: sym_byte_key(64)),
        (JWAKeyEncryptionAlg.PBES2_HS256_plus_A128KW, lambda: sym_byte_key(16)),
        (JWAKeyEncryptionAlg.PBES2_HS384_plus_A192KW, lambda: sym_byte_key(16)),
        (JWAKeyEncryptionAlg.PBES2_HS512_plus_A256KW, lambda: sym_byte_key(16)),
        (JWAKeyEncryptionAlg.ECDH_ES, lambda: gen_ec_key(P256)),
        (JWAKeyEncryptionAlg.ECDH_ES, lambda: gen_ec_key(P384)),
        (JWAKeyEncryptionAlg.ECDH_ES, lambda: gen_ec_key(P521)),
        (JWAKeyEncryptionAlg.ECDH_ES_plus_A128KW, lambda: gen_ec_key(P256)),
        (JWAKeyEncryptionAlg.ECDH_ES_plus_A192KW, lambda: gen_ec_key(P384)),
        (JWAKeyEncryptionAlg.ECDH_ES_plus_A256KW, lambda: gen_ec_key(P521)),
        (JWAKeyEncryptionAlg.ECDH_ES, lambda: gen_ed_key(Curve25519)),
        (JWAKeyEncryptionAlg.ECDH_ES, lambda: gen_ed_key(Curve448)),
        (JWAKeyEncryptionAlg.ECDH_ES_plus_A128KW, lambda: gen_ed_key(Curve25519)),
        (JWAKeyEncryptionAlg.ECDH_ES_plus_A128KW, lambda: gen_ed_key(Curve448)),
        (JWAKeyEncryptionAlg.ECDH_ES_plus_A192KW, lambda: gen_ed_key(Curve25519)),
        (JWAKeyEncryptionAlg.ECDH_ES_plus_A192KW, lambda: gen_ed_key(Curve448)),
        (JWAKeyEncryptionAlg.ECDH_ES_plus_A256KW, lambda: gen_ed_key(Curve25519)),
        (JWAKeyEncryptionAlg.ECDH_ES_plus_A256KW, lambda: gen_ed_key(Curve448))
    ]

    CEK_ALGS = [JWAContentEncryptionAlg.A128CBC_HS256, JWAContentEncryptionAlg.A192CBC_HS384, JWAContentEncryptionAlg.A256CBC_HS512, JWAContentEncryptionAlg.A128GCM, JWAContentEncryptionAlg.A192GCM, JWAContentEncryptionAlg.A256GCM]

    def test_gauntlet(self):
        for alg, key_gen in self.ALG_SPEC:
            for enc in self.CEK_ALGS:
                for i in range(5):
                    enc_key, dec_key = key_gen()

                    if alg == JWAKeyEncryptionAlg.dir:
                        enc_key = enc_key[:len(JWA_ALG_MAP[enc].generate_encryption_params()[0])]
                        dec_key = enc_key

                    plaintext = Bytes.random(128)
                    jwe       = JWE.create(alg=alg, enc=enc, body=plaintext, key=enc_key)

                    try:
                        ciphertext = jwe.decrypt(dec_key)
                    except Exception as e:
                        print('Iteration', i)
                        print('Enc Key', enc_key)
                        print('Dec Key', dec_key)
                        print('Plaintext', plaintext)
                        print('JWE', jwe)
                        raise e

                    self.assertEqual(ciphertext, plaintext)



    def test_recipient_gauntlet(self):
        for cek_alg in self.CEK_ALGS:
            for _ in range(10):
                payload = Bytes.random(Bytes.random(1).int())
                jweset  = JWESet.create(cek_alg, payload, aad=Bytes.random(Bytes.random(1).int()))
                jweset.i_know_what_im_doing = True

                key_a = RSA(2048)
                key_b = jweset.cek
                key_c = ECDSA(P256.G)
                key_d = ECDSA(P256.G)
                key_e = b"Eve'sTerriblePassword2019"
                key_f = Bytes.random(32)


                jweset.add_recipient(alg=JWAKeyEncryptionAlg.RSA_OAEP, kid='Alice', key=key_a)
                jweset.add_recipient(alg=JWAKeyEncryptionAlg.dir, kid='Bob', key=key_b)
                jweset.add_recipient(alg=JWAKeyEncryptionAlg.ECDH_ES_plus_A128KW, kid='Dave', key=(key_d, key_c))
                jweset.add_recipient(alg=JWAKeyEncryptionAlg.PBES2_HS256_plus_A128KW, kid='Eve', key=key_e)
                jweset.add_recipient(alg=JWAKeyEncryptionAlg.A256GCMKW, kid='Fred', key=key_f)

                all_equal = True
                all_equal &= jweset.decrypt(key_a, 'Alice') == payload
                all_equal &= jweset.decrypt(key_b, 'Bob') == payload
                all_equal &= jweset.decrypt(key_c, 'Dave') == payload
                all_equal &= jweset.decrypt(key_e, 'Eve') == payload
                all_equal &= jweset.decrypt(key_f, 'Fred') == payload

                token   = jweset.serialize()
                new_set = JWESet.parse(token)

                all_equal &= new_set.decrypt(key_a, 'Alice') == payload
                all_equal &= new_set.decrypt(key_b, 'Bob') == payload
                all_equal &= new_set.decrypt(key_c, 'Dave') == payload
                all_equal &= new_set.decrypt(key_e, 'Eve') == payload
                all_equal &= new_set.decrypt(key_f, 'Fred') == payload

                self.assertTrue(all_equal)



    # https://tools.ietf.org/html/rfc7516#appendix-A.4.7
    def test_json_equivalence(self):
        full_parse = JWESet.parse(b"""
     {
      "protected":
       "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
      "unprotected":
       {"jku":"https://server.example.com/keys.jwks"},
      "recipients":[
       {"header":
         {"alg":"RSA1_5","kid":"2011-04-29"},
        "encrypted_key":
         "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-
          kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKx
          GHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3
          YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPh
          cCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPg
          wCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"},
       {"header":
         {"alg":"A128KW","kid":"7"},
        "encrypted_key":
         "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"}],
      "iv":
       "AxY8DCtDaGlsbGljb3RoZQ",
      "ciphertext":
       "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
      "tag":
       "Mz-VPPyU4RlcuYv1IwIvzw"
     }""".replace(b"\n", b"").replace(b' ', b''))

        flattened_parse = JWESet.parse(b"""     {
      "protected":
       "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
      "unprotected":
       {"jku":"https://server.example.com/keys.jwks"},
      "header":
       {"alg":"A128KW","kid":"7"},
      "encrypted_key":
       "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
      "iv":
       "AxY8DCtDaGlsbGljb3RoZQ",
      "ciphertext":
       "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
      "tag":
       "Mz-VPPyU4RlcuYv1IwIvzw"
     }""".replace(b"\n", b"").replace(b' ', b''))

        relevant_full = (full_parse.protected_header, full_parse.unprotected_header, full_parse.iv, full_parse.ciphertext, full_parse.tag, full_parse.recipients[1].encrypted_key, full_parse.recipients[1].alg)
        relevant_flat = (flattened_parse.protected_header, flattened_parse.unprotected_header, flattened_parse.iv, flattened_parse.ciphertext, flattened_parse.tag, flattened_parse.recipients[0].encrypted_key, flattened_parse.recipients[0].alg)
        self.assertEqual(relevant_full, relevant_flat)


    # Generated using jwcrypto

    # from jwcrypto import jwk, jwe
    # from jwcrypto.common import json_encode
    # import os

    # key_a = jwk.JWK.generate(kty='EC', crv='P-256')
    # key_b = jwk.JWK.generate(kty='EC', crv='P-256')
    # payload = os.urandom(70)
    # jwetoken = jwe.JWE(payload, json_encode({"alg": "ECDH-ES+A256KW", "enc": "A256CBC-HS512"}))
    # jwetoken.add_recipient(key_a)
    # jwetoken.add_recipient(key_b)
    # encoded = jwetoken.serialize()

    # print(key_a.export())
    # print(key_b.export())
    # print(encoded)
    # print(payload)

    def test_multiple_recipient_decrypt(self):
        key_a              = b'{"crv":"P-256","d":"Yqi0BX_Y_YPX7jlDG-aDhowmX8UAz9KUSd5poMawows","kty":"EC","x":"9_rvQO4FGGrkoTU8swxqquy8i3c6IKUoyp4SnVA7CO0","y":"DrX6U_IiA4Z2pEquaAwdEjFXQNPGn3kCjOcDym_NbQ8"}'
        key_b              = b'{"crv":"P-256","d":"ppafhcC-hZ_A-R-3o6pTiJClqQUSCLTToqqn-QIpiNo","kty":"EC","x":"KogO6j-ZAb1O_9vWrJiEar2fHUXwqRTXbcaJYz8sxMI","y":"yyAFgMiPCMNaEL3j-x0yKjZZaXDM82zcU5dqn2jaJes"}'
        token              = b'{"ciphertext":"sGSM08SMiq6ehpTZ2rNQ-H4D2duNHzlopO4vEB_zLszn8tuDnUngI98hrR939Omdn_wIHN5i3sKror7lSOmplES2jTweN5flj0DlOu2YyHM","iv":"vbfxTPEaNTiaDJ5LPQscmA","protected":"eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZDQkMtSFM1MTIifQ","recipients":[{"encrypted_key":"f3sa2eoLCxiXXBhL2HVhM-AZ6JwSpC9fYgWzqsdeRiz4ryHwAhduxBG2OixYwmbruKdCVDzx9lEWWmcXWXZsBYiy-36_nAxI","header":{"epk":{"crv":"P-256","kty":"EC","x":"cgYPhC1wsuXYBk1-F6Ilk6I2XJZYlcvoMIBY7qrVS9M","y":"6S8xOHn9dLrbh_QEqPnUX0-mDKmZW5D5QgZLf00-HrY"}}},{"encrypted_key":"ypHLnE-vg9gMJAGA-wADzPtt07-LG-DgWHjtV4GLkeiJ1fLv5T-j0q0HUGoS-folRAZC1muDxs-t4VA-PDzWT7BWdKH-kdeO","header":{"epk":{"crv":"P-256","kty":"EC","x":"BfFUR0-hViaGNzvshK2Il6gMYAdX_5achWaDXWH1Wjg","y":"zJnsQZy-ct5zNxulEVnOHxfzC63R9N9UnI7Ptyp-9jU"}}}],"tag":"61TTW30tmIOpaOn3sG0HKhrvJu2lBCeEmPJGuKG-PSU"}'
        expected_plaintext = b'k\xb3\x03\xb3\xd0\xa2\xc6Y\xdaZ\xbae\xe7\xd8%\x9b\xc0/\xe1\xe1\xbb\xc6\xba\xb2\xf47ZJ}\x14\x91YP\x17_\xa7\x85%[\xbd\x8e~\t\xc2\xd5\x16G\xe6\xf8jl4\xd3\xb5\xef\x93\x02g\x8d\xb8\x9e\x89f\xb1n16\xc8y\xd6'

        jweset = JWESet.parse(token)
        pt_a   = jweset.decrypt(PKIAutoParser.import_key(key_a).key)
        pt_b   = jweset.decrypt(PKIAutoParser.import_key(key_b).key)

        self.assertEqual(pt_a, expected_plaintext)
        self.assertEqual(pt_b, expected_plaintext)


    def test_flattened_recipient_decrypt(self):
        key_a              = b'{"crv":"P-256","d":"FZHDOPo48KsOphUQdvmHLVEY2mffLfPaOB59EgLDMXs","kty":"EC","x":"vwciGLXnl5r3yNFV7dVPifrcroFjH0uY8ACf7CuT5H8","y":"jDOdNnJAnVxQOb7JCUMjqaumkwqsajBOBAUHM574sG0"}'
        token              = b'{"ciphertext":"61z9TaHW65aMaQ7uAzwvmAHqMx-gEXy8vfBzB4lGWtGq8wgLOWMljd97YywuOkmJBAGX6jfOV7dz1gQmhh4XNr6KVUJ6-l8mLtNXMPQdIiA","encrypted_key":"-ls01sJ7z-Nkz-jKdVqo_u2wSWrmg7Gnksi_8kmbO-yBW9Tl9dVgri_XWLev3491BNSuom_0b0vuwfmPuvOcqKDfd_1H8b-g","header":{"epk":{"crv":"P-256","kty":"EC","x":"qZ1sKT_eMSWLpcVJSb9tEyDUHz5fH97MNGk_V3ddT8g","y":"vqlJFmSIoJeusn6SX6FRGf1gm-tQ1d449iiVY97ySbk"}},"iv":"_9W8p0AetukUguXyPnqwAg","protected":"eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZDQkMtSFM1MTIifQ","tag":"gHgjs24TrXCdmTbqtyZooo665fMFNFtcn4p1SHjwmNs"}'
        expected_plaintext = b'\xac\xdd\xe2\x93A\x05\x82lC\xa2\x82\x84n=i\xb3\x8c>\xa4\xa6\x0b\xab\xe5\xf9\x15Zb\x99\xc2(\x97\x95\x92\xd2\r\x85\xc7\xb6l\xf4I\x960\x1f6\x15\xba \xe1Y9T\x9b\xf29-\xdd\xa7]\x9d\xb3\xafY\x0e\xbc\x83\x1a\x94\xdd3'

        jweset = JWESet.parse(token)
        pt_a   = jweset.decrypt(PKIAutoParser.import_key(key_a).key)

        self.assertEqual(pt_a, expected_plaintext)



    # Generated using jwcrypto

    # from jwcrypto import jwk, jwe
    # from jwcrypto.common import json_encode
    # import os

    # key = jwk.JWK.generate(kty='oct', size=256)
    # payload = os.urandom(70)
    # jwetoken = jwe.JWE(payload, json_encode({"alg": "A256KW", "enc": "A256CBC-HS512"}))
    # jwetoken.add_recipient(key)
    # enc = jwetoken.serialize()
    # compact = jwetoken.serialize(True)

    # print(key.export())
    # print(compact)
    # print(payload)

    def _run_jwk_decrypt_test(self, key, token, expected_payload):
        jwe = JWE.parse(token)

        self.assertEqual(jwe.decrypt(key), expected_payload)
        self.assertEqual(jwe.serialize(), token)

        new_jwe = JWE.create(jwe.alg, jwe.enc, expected_payload, key)
        self.assertEqual(new_jwe.decrypt(key), expected_payload)


    def _run_oct_decrypt_test(self, jwk, token, expected_payload):
        self._run_jwk_decrypt_test(JWKOctKey.decode(jwk).key, token, expected_payload)


    def _run_pki_decrypt_test(self, jwk, token, expected_payload):
        self._run_jwk_decrypt_test(PKIAutoParser.import_key(jwk).key, token, expected_payload)


    def _run_ecdh_decrypt_test(self, jwk, token, expected_payload):
        ecdsa = PKIAutoParser.import_key(jwk).key
        key   = ECDHE(d=ecdsa.d, G=ecdsa.G)
        jwe   = JWE.parse(token)

        self.assertEqual(jwe.decrypt(key), expected_payload)
        self.assertEqual(jwe.serialize(), token)

        new_jwe = JWE.create(jwe.alg, jwe.enc, expected_payload, key.pub)
        self.assertEqual(new_jwe.decrypt(key), expected_payload)



    def test_decrypt_a128_cbc_hs256_0(self):
        jwk     = b'{"k":"6q68Q3mm_qWRKCgqCj9_GA","kty":"oct"}'
        token   = b'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.EtB4-hoy0Fop_dk6VuzlNNOzYy_iFSdMLfBqNt52EbZtsoMlWdcXxw.MLEXJeSoaYswVHf-A2gkew.2Fi3gqTg5XPAPn2C2CW7ggi8HFpOJCYkfj0ehky5PsPFDCw3lxYYZFIYrItmaEGBxILB_7nFWqb8P_EMzfuKNjSSVTPryhEe8zfV3nutF-Y.vzUW1x12fS4NF5h6h5NYMg'
        payload = b'+HT[\x87/\xfcY\xf91}\xf0\x1b7\xb8\x12\x0c\xd8s\x05\x89*rT\x14|\x1bb\x00\xed\xe39.@\xbf\xe3*\xb9\xc7\xd9\xef8#(j\xd1\xab\xa13\xc41\x87\xb3\xc0\x14\xf2w\xeer\xde\x87 n\x16\x1b\xce\x16\x9d\x91\x87'

        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_a128_cbc_hs256_1(self):
        jwk     = b'{"k":"G2MJAwdeuhnbda0nirocqQ","kty":"oct"}'
        token   = b'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YhhXzMVdePa7gHiiGpRxaCOPn9AqwK2culp4lIwxSACmvvJs1JBMmw.7oHeWchQvtedhUMgFRLknA.tf-AjkH15Rsrw9kEoEPkEHr_9CdW9fidb3juOn7jCK1x4bMbR6yFSSq7sDpREAPM64W2sIHgx1O0MYypUMR64Sfx3cnXvAyFW14qtkLvtGs.Bgtvpx13j07HzMRYzh0aQw'
        payload = b':\xcfjx\x95\xf9tK\xef~\t\xa8\xc7\x08\xd0\xeb\xfa\x84\x1a\xcfN\x86\xe4\x81\xa1\xee\xf2\xd2\xf6#\x1d]\x1d\xdb\xc5\x14H8\xb1Rjj\xcbO\x0e[\x8a\x99\xf6CM\x02\x9c\xee\xb5\x87k\xabP\xaa\xfc\xa3\xca\x9aZr\xeb\xafZ\x1b'

        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_a128_cbc_hs256_2(self):
        jwk     = b'{"k":"L5zkUQkOo6GsSIWAig6ghg","kty":"oct"}'
        token   = b'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.uol5DtoTKRucHEUOg8XVWgoblu7y516h8YghF-3ZGg46wAAzB6LNtA.PUH2gBv6DLEQWfoQDFhQug.LbJ09LY28sV9AmIfnOyherIlKgMI5Wzxv5C8Sy-DavIFcs0g88T2mCqfrBkZh4anthxAzRQXzpIV_FtxB7zlggatsYp3jmLf9o1AdwG6WS8.TvfRunNy0_pNivh--YLU2A'
        payload = b'\xc7\x08<2\x07\x94\xf7=\xea\xb6\x9d$\xbe\xec\xda@\xf5\xb0)|\xd3\xa0@\x17\x05m\x10Yr\x85\x97Q\x9e\xd9~\x81\xda6\x86\x84\xcf\x9b5\xfe!\x95\x86\x02\xa8\xc4),=\xea7\xfb\xce\x04\xff\'"\xb4\xbc\xebRQU.\xe9\xc1'

        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_a192_cbc_hs384_0(self):
        jwk     = b'{"k":"WENl4KsyjyP4qoliVYzgz-kx8jjie1Yv","kty":"oct"}'
        token   = b'eyJhbGciOiJBMTkyS1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0.Bf4uyGu-sXT_D_K6RLhAK_qQAmeK2BeVulEP0yBAtpSeIA_ztaraIqV3zci13jVBuZOnrfnCAZQ.E1EGw0QX7K_MNH80v8K8dg.7HK_eeZzE9h5PetuzKKYPdbroL6dmDN6FZ3NpOH911PcCxlogoSLZNzgGzDuxiyGWzlfWKmjWKYM8DDXWrIJHPNan-Xf-Bevll4xK4BZUzQ.-IRW7-X8cZt7UAEEqaHdifg8aWL3BNVj'
        payload = b'v\xfb\x7f\xec\xd1\x89\xf3\x98O\x18\xddp\x95\xbd\x9e\xfc\x9b\x9a\x07\xd7E\xeb\xe0\xb8O\x90\x81\xb0\xde%-\xcc+L0a6"5\n\xf0x\x8b\x05\x07Z\x9d\xaa\xda\x96\x1cH\x175\xa6\'\x9f\x13.r\xf2\x1fk8\xa2\xa3J\xca\xad\xe8'

        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_a192_cbc_hs384_1(self):
        jwk     = b'{"k":"bGcY0xF-GPKTur7zgA1Up_PsyV8kizGM","kty":"oct"}'
        token   = b'eyJhbGciOiJBMTkyS1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0.BioB5jt9H79rFrVvIm4O43FOj3oe7dVe0uft5wQi8QlwK_6NGfGw70pjVJeA-QQqQbRS3yGUci4.rdnS7AvKGipLfR01c4IjDg.wjpZSf0nJR7mPEb0iZS1YdMHlbWgGk0i2HDwCRRWGphDtlE4zqvqJOux5cTo-8n8DrjvCH0EoEgRI_uqN5CX_SocW4Sctz5GXWpbxMVRm5c.LDZ6grSOISdVCNGjuOvc7GXSoVoNWsGF'
        payload = b'\xbe\x03\x16\xf6(\xfe\xe5\'\\\xd4\xa0\xe5\x80\xac6\r\xaf\x0c\xcc?\xcb\xf2%\xf3\x14\xc3\xed\xa5\xdd\xa6\xc9 o\xae\xbf\x0b\x15\x9aA\x95\xf3\x82\xdb\xea\x89W\xe1A\xcdp\xeaa\x11\xeaB\xf3T\xafD\xc2"\x81u\xfd]\xc5\xa3\xc1@\xd4'

        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_a192_cbc_hs384_2(self):
        jwk     = b'{"k":"pe43EUNzyQP7t2Olhesn5VrGenHrGFZb","kty":"oct"}'
        token   = b'eyJhbGciOiJBMTkyS1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0.Nn8doDRyujwg02M3Zvu9bR386YfiZxISaxkbahdkIe_fiIg_6OL5Ww99oGyDFDijHCFq2Nmi-5I.HO1Ht4dSkw8rIYJsWPpM8w.oZGbneQYTvSF0Y1Jt9FEWsp1IoYWtfJu956dfCgbukb7ZoQfS6mm8w0xann62OoZaPrTEqsqPhYpx7nOXj_VQ4J0550FU4261b4l6PPY0eM.8jyC7xXAWBe3sa5J0N6XsFvX_nxN1s8F'
        payload = b'gr\xc0\xe8\xe3))L\xf0\x01\x0b\xbdw~>\x10KP:\xaa\x86\xff\r\xef2<\x16b/L\x16\xfb0\xcek\xdd\xc4\xa8\xf4\xef\xf3\xce2\xb6l\x97!\xe5<\x8c\xc15\xef\x19L\x1d\xfa\xbf\xa8\xea\x03\x97\xa3\xc6\x19At\xd6\xd2]'

        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_a256_cbc_hs512_0(self):
        jwk     = b'{"k":"F64Tqh4rRBvRpJokvU2sTjkCkLgP8_UR-nm0VzdSVD0","kty":"oct"}'
        token   = b'eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.r4URBcAtwqHAq-cXdWxkjRWmhswP4feAdwLzmHCEYLMBslgAFyLAP629fZOMLcpTZLrA0lYVBRyb_0vWeWoCBhsKcdkBW6wp.hLSK5p-yvX7CQZLyRxYXVg.7kcAwXjEe0BDHkDqUtolCa_FnJIpQB6FBTIDqOP6ogs.iefgVR6P2Dco7s8Y92bhmmFoBNYCCrai4ZHosjCzy2s'
        payload = b"My Encrypted message"

        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_a256_cbc_hs512_1(self):
        jwk     = b'{"k":"C62n-Fsp5nb77Jcg91RdFFEDzNtad1SDI5Rkowh4ZAw","kty":"oct"}'
        token   = b'eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.Fs9VhFVHiPwRNMor-p83fqeCNVdqBcBu7r3X_oCg6MFRRgq9E5CqBfRFWFmkLd9A9twrDqkKVLXmrFznfiyViG7_VG75cZK4.hm-odyKNkSaLJiJ6Wjiisg.3NXRtYwdVB22Cs6NhIDgUN7-m_Oui6Gv0ZpW_1UcFSzY3aAxI6DvyFGTLjgN1Nsn455HlITyOp5URLVp16XeiA7NMu6ZTHPlmY32IMNz7Bk.UZDs8w_i-Kx5Nh9bZu1BXMXQ2o3u_0sM_n3wb0vI6Wc'
        payload = b'\xda9\x80eaQ\xe6\xac\x91\x0bN\xc7\xef]`\xcc@\xba\x01\xd8$z-Z\x9c00i\xfe\x93J\xfd\xf5\x95w\x8f\x9aN\xc4\x7f<\x1d,P\x80[\x1c^\xd5\x86\x83\x85\xda\xccXZ\xff\x10\xac{~R\xd4\xad\xc8\xed\xd45\xbd\x93'

        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_a256_cbc_hs512_2(self):
        jwk     = b'{"k":"gKqLl2fZVNWDZGFqqSDK20G5dM6q7JXE_H2WI6Ng1fs","kty":"oct"}'
        token   = b'eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.iOGzjnx6rpr5RgePy6SoKw1Jw8nyBGPkZYxUvxEMlsE1CwFFapUDmfSP43ZpRSBjHiTc0SunIRzjexlX9w4KLWi4Nn0ayYOm.PKj9HkyIsSTuLVZtbfRUlA.lkGaJEMHzBvZVZ6nNZk0wGNoAs7J64lkYCWQ5G7K0MEu3P18sBQ29NzwFi0gwEWRhlzR8x1RuW9K_yXQ39IQrD72IC_cZMNl83OFbNJf-ck.PE6hrOg6W2fu2wsyPwb8jIz-1KfRMs4Tf--AyLgRZ7o'
        payload = b'\x01\x13*@j\x99l\xccT\xf0\xbc,\xaf\xec\xfc2LQ[\xa7\x98\x94z!\xbe\xdcm\x8e w)\x84S~\xf6\xfa\xd5\xbaz\x83\xc9\x01\x86\xfdl;\xb3\xb4%b/\xe3\xfd\xb69La.\x1d\x1f\xe5N\xcb@\x14\xa8\xc7#\xd5\xad'

        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_a128_gcm_0(self):
        jwk     = b'{"k":"9II9oiOrDCWMuL840oP1QQ","kty":"oct"}'
        token   = b'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0.53c2p8ijS7yN8CiHg-I5a_ls7t1cWOzk.babG4HJDDWOWU79M.LA4Bqrrvy0S6AnsCljdtXnAgQ5303iopTAr_d4QJU2xtUnTrIhbN8_oFPnv2ciRPCXkrFu6pZZx2jAAGNuEP8pRlL9kkOA.VqCFTC4oYvbdyudmn_j80g'
        payload = b'Q\x06\xbav\xe7\xf8\x8d\x94\xf0/\xceY\x1c\xad\xeeOMH\xad\xdc\xa1\x82\x1f\x99\x90\x94\x97\x8e7b\xc5\xbd\xaf\xc3cJ\xeb\x9f\x04\xfbx\x89\\\x02\xa5\xaf\x94\n\xee\x98x\xc1\x8f\xa2*\xd4\x174:\xa4\x02\xb9\x85\x9c\xaaR\x01\x11!\x81'

        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_a128_gcm_1(self):
        jwk     = b'{"k":"52ZGqnldJ2mSsXEFHOwLVA","kty":"oct"}'
        token   = b'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0.g8RiWeNBNhY-wvx-Z-QGnmqo6UN5oOoP.fHI1FTnTHbiT_Euw.X_BaRu_vRkDVQuAG6KZHM4xzkGf9RI1kJ_3V2Dr-8hJGtOKlx-tjU4oKp0IBKTFvKjMCWkCe7lknHOH6YqdiQwPd9wdnUw.mrpIK1cNF1k1I9PgjOZIxQ'
        payload = b'-\x0f\xe08E\xcdw\xb3\xd1\x8e\x16\xe6\x03\x9c/\xd6!UYY\xb9W\xfb\x17\xa71}\xf9\x126\x9b\xf5_H\x00\x9f_\xbe|\xc4\xf0\xf3O\x15ci(y\xafv\x1d\x11\xdd`\x1f\x19@\x13DeG\x15\xdc\xc1Y\xd6WZ\xddf'

        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_a128_gcm_2(self):
        jwk     = b'{"k":"SbSyMa1IZrCzcXFfTGxvIQ","kty":"oct"}'
        token   = b'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0.RrNN6x4Kk6GawBEqnbN5B9kzfeulOhbx.NqFZro64bgXPJLLV.9k0xRHJDaovTUlYy1IVqoebH8Wr5iA1yJEmOl-bOtIAesnvXEZ4cvrJr2hzKRCUM6DbvGL1oTH5oyoPUgJbQc9uBBReUVg.-ctXH8QyZKg9jtozpukbVA'
        payload = b"^g\x16P\x99\x91`wnqLg\xd9b\xac\x97\xf1\xb0\xc1\xa8\xf3\x98\x85Xn\xc6\x8c\x8c\xd2W\xa7\x94b|\xfa\x04\xdb\x94U\xfd\xbb\x93\xe2'\x0eS\xd4!~+\xa70\xd2\xd8\x8a\xfc\xa2\xfbx!\x06\x8f\xff\x99\x8c\xb7\x02\xaa~C"

        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_a192_gcm_0(self):
        jwk     = b'{"k":"h5rKqvafW-cZImDHV63drnUIP8gf76gE","kty":"oct"}'
        token   = b'eyJhbGciOiJBMTkyS1ciLCJlbmMiOiJBMTkyR0NNIn0.2qPDtDil_J9TM8R2Gqu30-YU7UNr9IR4qVgV2VLBZwU.-w3KwRhusO6QfBSj.6Q5syUu8JfzAUqqHeEDrG0lJWWts9beKwlPcdysvhL0pl9s2rVkrY69CFMYhX8wd5bNidqeG3YcUF6MEEO1hUEiJv2zqYw.1aMU3DDluG0I9KBJhp5nVg'
        payload = b'x\xfd"\x10m\x87\xb1\xf5\x7f\x0e\x8e\xce\x02\xd5q\x14\x85\x17\x85\xf0V\xa4\xac\xf1\xe7\xa76\x8f\t\xbc2\x85\xa2\x91#Jg=\xe6:^*\xae\xebo>\x91\xf4\x87\xf2\x1d\xec\xae\xfd\xfb\x8b\xf0\x1a\xfe\x0c\xcb,\x82qi\x13\xcd\xd0=\x17'

        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_a192_gcm_1(self):
        jwk     = b'{"k":"pEMd1zZ2DA1oVkVLG9zgeLUz0mKKrSbN","kty":"oct"}'
        token   = b'eyJhbGciOiJBMTkyS1ciLCJlbmMiOiJBMTkyR0NNIn0.M3Y6qe5jvwsWCXa-_om6H6KFvyzW4O3hGTM-0LPbcoY.S6DJaoKAP2S_vHQW.FCphT7WYEQ_3PvQcLtV2Bj_rv76JEakc_qfcmkt_CDD7War2WTWlEJpicrFqnVxOjpiJm7SjFyRIh3G4Lg_Bt3Y7zofluQ.2JJdZJLPG8N_8yIilM2Jfw'
        payload = b'\x8b\x14\xb8&&\xff\x9dt,\xb9\xf1\x99r\xc1\x9bF\xf05\x05\x15%x\x9e-B\xa4\xa6LVOY\xe5J\x8b\xb7\xed\xf7\x86\xa7\xbe\\L\xed\xec\xdd\xc3\xf3\x84\xcd\xa5\xe0\x97$Ll\x92\x96\x89\xf9\x9cu\xe5f\x19\x00dsu\x1a\xfa'

        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_a192_gcm_2(self):
        jwk     = b'{"k":"lAT52FUTWQfuWsPh5gJb8NpGTyU3y0X3","kty":"oct"}'
        token   = b'eyJhbGciOiJBMTkyS1ciLCJlbmMiOiJBMTkyR0NNIn0.h74o3AN9_GdVd4CfFcMM_ObmsSvfMmcSj8qhJ4oVYk4.rIJ3pW4FdTKgV7Ce.95wTXVz8ss_2qQsYCQuvJ_CEoTziJOK0W2eyrWwWjHHO0be8dJ4o5eersgpkv-Mg3OGrQwrYnkPaC7mQ1R7eVYZ83haYRQ.FLecfd0aTDrxafG_NXdd6w'
        payload = b"\x87:[S\xeeL21\x8d\x88\xbd\r\xe1\x97t>\xa4\x84\xe2\xec\xd2\xf7\x1f\xe0\x91\xaf\x07\x0f\x08\x8a\x96\x9b\xcc\xaa\x17\x0e\x13&\xb1LF\x16\x15-Q\xca&1'Ng/;\xcf\xd7\xdf\x80\xb9J\xefRDwj4\x04AW\xad\xf7"

        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_a256_gcm_0(self):
        jwk     = b'{"k":"m55qlpYZVqEdaBfRMOJdOej1m8pjOWKA_ed6CdQxEF4","kty":"oct"}'
        token   = b'eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0.z4cRfR-TRmooEOd34fRymSOe9lDZOnlKKJhCpgVRkkpNYiQZRQDIpg.CMcKN0E_LMZcTug9.w8Ow32k_1ZTdeo4fYH9yfmG-RNcR7IG2U3MRJHAMmEMvD8gH3Ru0iIZefQv2vFjuBRkmnwvPH3gUvyzgJpkfh_EwXKlTiA.DJaa8mrlASXJFsPtIx0NdQ'
        payload = b'\x08\xb1\xa9\xa9\x91\xe0n\x8c\xee\x17\xb5\x9a\x86b\x13\xear\xf9\xf9\xd22\x7f\x121\x1a\xa7@\xa5\xef\xb8\x17\xe57,\xec\xff\n#\x1aN\xe4\x9bT\x18\xc3\x1e\x196\x8f|\xb3o\x9e\x8b\xb8J\xe5\x88\xb9[\xcc\x97^\x16\xb4%ZP\xb3\x10'

        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_a256_gcm_1(self):
        jwk     = b'{"k":"rBIeRdN8oT38qe5BiP4kjn4-PuSs310wSjnC7GBVGaw","kty":"oct"}'
        token   = b'eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0._A7omfE5lyKs0SE4vEaXeWOwr3BtI16GOc9XldlEKxAwFpl61A9RRA.0jNZGMpNVcQkLKM3.YQvUspkOviw6RNOqi_h_RDARjCyZnEv5SuEz4oC6sBk9jGegECGP5syNhrJ4SSG43uhChoE4ZRfUvIhz7aVuI84xyxwG8A.JKWIvl3FApZp_AwtqhHjew'
        payload = b'\x0c.fS\xa5b\xe5\xdaF\\?"\x94\x12\x81"\t\t\x0ci&s*\xda\x90\xe1\xf2\xf3\xb2\x14\xfa\xf7-0\xbb\xc4\x10\xa1fTx/\xbd\x83\xaf<\xd1\xb3QH0P\xeb\x12\x8f\xbc\x03n\xdb\x91\x8fK\x98pMv\xe7AX\x8e'

        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_a256_gcm_2(self):
        jwk     = b'{"k":"8xddL_sESGpxz6ohxCNdpJXy3kQkRl0VuvdFktGs9E8","kty":"oct"}'
        token   = b'eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0.Fglx18uwvyOkcrWFhQHs3hF8pTsRc3ABlWOJwKM8K3kEkZIR9rP0xw.CpVuAxmbMXFjQh3f.V5Ia-4phZPYBsJP2c4U2iVKF57lUDKJU3euuerOqtncSlxhT9Gp5-XH4UaMYBUB2BOa_O2Yvap904C_CNY-rDnKXMHlQng.CSLrOLYwV4qaSMqzy0J-3A'
        payload = b'|.\x831\xfd\xe3\xe3\x80\x95=\x9e\xe7]\x87ph\xa6\xab\xbe\x8e\xd4\xb8h\xe4\xf3\xa0%\x03\x89\xa6\x9dXT\xa6\x02\xe5Mt\x0e\x93\xe3\x854\xd92s\x12\x96_\xc7\xdb\x05&\xd8\xe0\xba\x901!\x7f\xc5\x95%\xbb\x16U\xb0\x03`p'

        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_rsa1_5_0(self):
        jwk     = b'{"d":"BuY5Sl438Z2A7Mh0AkMUu315I5kpwovsivSPg0zJqxlfghBAJrdyVKi1EknYkG8oCXLN9oz6BNQrf6gV5QKKZeXvBUC9yeC9aZXgB66YKhePRynL5pj_EDDVIcPHfTavfVnzYwebIHSIDNlLIaVKLLLOpA7ZMuLjucf8S1HBCHe2KijaiiqYRfP0CZ6RpLiQ1kOj8hpBWcFC2Md7YFfF3ym1U--p-VCivnmxfH41N5vRY_gsPvY-ynAInom2MvZedb0TEVrfTtHzrYCjGSiVw30v_usaT3Di1-HkPih4K5kJQBXFuMl-MOv_W4fNVsZUpxijjrdCePheTlXk2qOngQ","dp":"pVsaDqLdI7zWLIIPpGbmm9JGJ6HJ58sThfweiYuhGmEvge4nJV8D0am5T0YTWLx8_Oz6WhGQWZZrpQ0MjXyGiYRNbSktjtFCq0PuClauYxqLknzytaPIEpXX75fVqmdyiXMcxTkNJIn9t7XYZT4WbjwO0kAQqduBUzwXJ3RAQy0","dq":"CZ511x1S3Ht67vzrfvwddV2QceqFdym_pvK_-WH4LVYc9jEKfYqhbvPDPkDDbNqHA0Wv0j7_uH9xCoMOc2RRgVpRe3xXwRCVXrXNpHY8W-gmBT9v5uSJB9Y1iI3xfLNG1RJT0BgF_5e1nc_5ljn0cdz0Z9Acc1CVaAeNY9624CU","e":"AQAB","kty":"RSA","n":"-zM6HF_m8fvPZpiTKNSfFe50NKpKe7A53gYKOFzd2b-EeJHzVmn2WAp8cZ-x0U-2IWZQ-Zdny2eVl9WNzyMv2VzcC1gKnM3WO6HLUJYqMgXiPHR9NiwKaKkl6oMF1IE84FjaBh1R7b838omrFa18TPCLyQeTBSHvmP1zYrWGkuMRD_ZJbMn46zRy34_oylO_7MM8XOZhUtqJxeUfYF-Wru51iDC3EBt7eIG-gzJHMEwOezGhdHWdtY2YejjInTqtKbXqqfUKve63_YoxEINVSfBohlkhzhh05mitcwZX1oLXv4q0V7_RjrlcBTR3RaHwEGHmi0no7myku5bS0Ylm0Q","p":"_huMltfSd3R1itC9ueo6YA_DXAcwRAd8wwotheF2OXv2Y-hznEVgB8PMT2aiDjm-tdwQJ1qHvdFwHEoJJsQuvOBH8ilHgsyYYJy0PZ3iFLcTkbhk6PhnnzkPNrCY0eMuLDPH-_P8Elz_FGy_K69ebnQvE1cZgVrJdRGGP8gmB7U","q":"_RIifK1EhxMob8x1jx5c2cWbcAQMGCxGXcR8-16bHH9ChgMnNxjeJVNd1KG6E7oaSdxZMotaSHgxh8TnR0xzRix7gmWqBf7PunFJ6zpa3QHx9hQON1XOF48YBhzHpTrW0zVtsufbyRc_XCSGPP-OHLbAq3kxX5RfBcA5FKrhXC0","qi":"5zGTZCG6j1bB5QqP9xG6B2xzjAOSUN2UAiNDTRipIFnGLLY366_FgunrtW1M5MpB4HJet8Tkh9YtPLIelg5LQQHWZ0w1mPpBWBeRSeZXPclAKu5yqx_2I_B_-dtH9na19SvXPBFaWDoFnMEd7K1U1vZPldEsvvfUp2R35KumVnw"}'
        token   = b'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.5HxgJMDbPh3N4PgVhTpRBH-TXNLocUtzEihe8TTfetK9__NjxWG0bqy_lWEPh3rqNIX3JvzkoAy_sROu2BmgzhY1vxEt7ixoNPowXJn1aJ32sfac0oMUpkH4Vo80PS55USi856-IkBWDqnXUv-fEgKKc61Dh08tHLMASBt1ZJSa2p2WuPFLUfcVtIuxoipAMbD_ql7XhLB8HsEQ3BTJEu4KTmjsNUBIxuKsPDfDUYNn3Njz1kpfXbDZhE-Gfo2GxMlcCw7zJdeByEZsGSw516-hdfD6WgLOxwCzM5haL9Vt530n0aE0oauvJtgxz_I3wWP8yTZyDOjxXml03AoqUxg.b4TrwRm2BjhDL6f1hDdqog.8ZwZMtD_iKuPKV1WXa1E5fV_uRCju099CYCVTG73bbCZbwJ4u3Q_UZSk9Jk2iXv5FfSeT3en-m8odyK8j--SB-O5kkBhPSQ0s96SJfWaK1I.c3gYfpFSUDv7SSqbZVs6W5qMOyhNbsY-w5H7GD6Wvjg'
        payload = b'\x08\x19\xd7\xe7L\x13\xd2\xb0\xf3\xfb\xa0l5\xb0\x9e(\xd4\x99\x05\xdbf\xb0$m^\xc0#\x11\xe5\x05\xfc4\xdc\xcc\xa9\x05t\xe1v\xc6Z\xd6\x86\xce\xc9)\xbe\x85\x15s\xc9V\\\x9fe\xe0\x9b\x03)*uq\xa0\x87\xb3\x05\xca\xf3\xbf\x13'

        self._run_pki_decrypt_test(jwk, token, payload)


    def test_decrypt_rsa1_5_1(self):
        jwk     = b'{"d":"YA27zlLAtCQQHjw5lSv9dxiBebv4Ncp1BOaPRhuS8IHccv1z3D7OtKgle5-lBBKLmwIpp-di3uohiRgbpeKsr2EbvfktCbHRrnXAp6fT2oBB9YgDwtkYmFJObuglrQBgbXf3P6ym9IYKpEaGf49071YERMv03QhJigNAMZJf_pMUKbVQVzSu6FBUAVqW9bMqTHrqySQjWEEO2LHPKR4NfSiWCEE-H6jwLF6R3C7Pz1_8wxDL0n7lQc-gP9cC6abHA9aFd6WYR0uRouoKngXai5kQG0zH3HrGd_u-JU2DbdAr1HrQ24ptRBN43h8lgqd5H6RjH5y_iyOJhlOo5v8mYQ","dp":"0AtmlTZ-U3NuaajH12CmApQPqh9tIO2Xjvm6RTDZx7FPYp8Dl4bJxjTl899WGLNFiStI3vvFdTCHzVWNspQNhz0Uw9Nc-7XMP3kpjpN4CiHK8wcSDIB9x9Y_jCICsMAJInOEQZ3uCHzZsnV9RGPKAln5ryHTe-ffCGzC_Svls5E","dq":"gAG-yC48r4ri0mJeWtpE0PmayG2cEOk3Dh_fW1KLmphvswfgNNMhKl9dgHc8ETLD7PGWonhnDKI2YGu45GMYS4em54ohnK_6fOxiDr2MjBgMkEKYjrq3rvzWWNTddos03UIOuAD4zAkb0TzviENo_Fz8vppiDmRSi_TN15tOWI8","e":"AQAB","kty":"RSA","n":"nqJFTGDjvk6DCYSC6k1XFzr15IO-mNGM-OhRrPDXFL7bM6qbAXSwCOvDg0SwcwicNGUAyz4zRoYR98Qcz4jnK4LyGtRnQyfBFyZBg4j8ibGLXL9me0_1RkPYS3F1rrC7OTsACvddsoCrM7aapZztQ7yLY2TZJrh65Ve0UhnGoT1WYB_Ao85Xx-mIOOvI7jS3CIvA95LRPTDR-FW6ubUxYs_8_sIjRVnRR56HUxAH_Z3qk0TBVmI75TxDUgyNZa8ufJGFAWMG2E4K6EwrZ0KnHk8bTqf9q7144xMFpHodwRLjBLcwsNyq7g-YhEq-XPOUGNwBKx_jpjSGnc--rhLa4w","p":"0oLs5F1HAa_PnBvpH544bkyJjlB6Xv1Rc5qllQSXuyTKTg5C8RrAc5kDmpFjkVnacewki8Ni1hVnHc-sPS0KDGXA3cCEnGNVkqfNyUseroa6vlI9ecJXjKJh5bC7VANwL5tI9LdhEkCRo6iFokIyvCWw9k10rlGhgzPj4bARY5E","q":"wOmU7h2vud-r95_KS75TIRGYIhlH6RiWyvWYTgv9svchW4IQkdMGUEmbpv7j-bS83vRV8qehUpHtqRBnCyHD0R3461ZlVCZOegDmi89Awj6yztiUr2xBTn3zTlrS07SlL9L0NYVn5wEHgfq94WTjxXkdslL_CII4zzZOALOPNTM","qi":"iv3LyHe-v9XIuJbjE714ZFip9IGMfGp0j56AOLPA3PpzH6EHus2vbXTJh-yUBDzgIySvSzyFSyAO0AbfJL7MaLGB1cyGn0n8o3OG_nwKcGMRRhVknZkE2-Qw-IXpfV7hFgSOawPuVtqutG08P2kehQ7My32zhTzldOuZsmugImk"}'
        token   = b'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.RfWeV9_byPkBl0CwJohMrS_LxOQMN8jqdOpkfLjxFFRT-QTlmbssSu5vIfjn8C4X_t4v6e6nsTC8TIlCwEYkbFJ8hLayrtz_lLHGUwm3QmELmdQg-N_IL5T0QVrAYVBB8DB25A2KB2UTDKepFjAANbOf4osPrto6knM298Dts6wd6-6LzM_5lnIWUJHemHcGtrX7iY5dlOiz8JdMx-WQqnFm0Q99kg-Z1ZdShl78bX-qCaguA4owoWdkYMcqOCpzQJbwI6lwTEoDaZs1vsh5zU-K89MxBg0_VNDmXtWbVoUNK0gZ0Yle6AK0tkwhVH4NNsLI4b0KphJST4p3FlSEFw.z-RJF_93q3klOyqqTM76dA.0Vlss3vr4dkrBsZ8s4s6z7SJfnpfgf71khafMN2chgL9TlSMRc4xX6fPDbmvixh1QEpKIqDgfE-VRHWtXcW8pDK0lGA2yX2yTSDg0ooGog0.np9YoKcLAosXvak4ICwe5fy7ZFOTPXCK8sd-S0AQmtY'
        payload = b'\xa5\xc3\xd2\x97L\xc9\xfe\xb9\x8e\xe9\xf5\xa8\xc2\x16\\y\x16\x04\xbe&\x13\x97\xe5Y\x89\x82\x9c\x04FV\x01\xcd\x1em>\x07\xa7\xea(\xe1\xde)\xffo\xea\xd4\xc0\xc9\rh?\xe5\xa1\x93\xddfiU8\xd1\x14\xc2 \xb2|\xcb\t\xa0\xd4\xa8'

        self._run_pki_decrypt_test(jwk, token, payload)


    def test_decrypt_rsa1_5_2(self):
        jwk     = b'{"d":"svXoJ0LWPRdhXpk6tkSDjNo2jQJdkK_0Ud_y07uXAAKjRr7lnJuOJ_2dRAOV7oxMaY_sHDLt4UEfowzUV1NyFMj05B-1ySP_sIRx0VnMJTumIWUtMMHocat_hhIoz6NyGGa9cVejjPt5JXZ6TSjivJcRNZPWT2GMzISZtCyalw7onPvH7RZ8laz363p62Y-1gMw2PwUsC17I3MHkYClQ5Jpd1jNizfDK6_l3Y_gL_y72uSDBO2mWC64gWsBC8KraJtrRAPkBlMB75H2Y2NbtjsRRzbJ9SI2pw69x0MHWKYge0lwxt1AloVKhrU2sWM_0K3LYoFa0RviIP-roAB7sEQ","dp":"p9e5Q_I2UCpdPvQh8Qa33YRAM0xDohnqzwI2Jj029CpPTUKc4gJuaMJcbu5ogJY20u0srZIK7W7mQb0qqO_-WC0z-6mAQFzfonF5ESoGx0v9jCK4fMh0T-VqMI8W1GCjJWT98iiD5QBS8DSRdFMLGgqcq8JJSbEceb0ABWP2J6k","dq":"shXIwN2f337ZTsN1mfiEETKAevTiL90np66DItDTyW6UntkVRvkBno-rINpRO66Du8aj8xgqBsGWsrc4Vqz1U-eFmmMjiXT08vAgyhLDN3Essqbf7c-WiQKVaT5kJA7hoHnVwTKVz8vql1kWcJEJHWxs4GWCtyZid_JRRxOUm8E","e":"AQAB","kty":"RSA","n":"00Cxfkl176NnQTnQiB05URySYzS9MhGqNy1HazjofIrYG2sCidRFwO3hO8R9X-fs9K5zzVRb9pt6nOD117Uyc0yQkfODTZkc-5Qhiir49rUzlEh14qkS3vrpCigaA7e5tWzL7-v0kUerfkfZGYJUlRefFDvCK_FIS_WblZ_3BCQQ9TXHJL910QALvrBR4to37ci9ZGfdQ9opIX8hVeUkPvcWVAEEj_gidj0ZYEKh44BbpDYSn8eeBYe9VXr3tRvQfSr3i92d3ZMKN_jYMoBFnk-1-owbef-dgdpkYTPBg2tm30j6IeY3NGcUSO24bHu2oFxmw2qgiFtYVUI4jyY6EQ","p":"69Y_qodGGkiAWl9D7CgjPPqp2_QNCC_Bhc6b23E8l0Xu2eiWGydmStjULM19m2ArFLbKacqhpdfSVpXRxoQNWWg1La81BO9Y93oNmrJ3rlg3uJsGHJFjcdUXKWySiwjgwkw45ruiVCF1UQrMuvHpvn9OjhsCfeDK6zTMlbUWwPU","q":"5VBfE-j8r5ihWJb_la3nGckz-dSHENEJ7FBfDQ6uIArGNDfz7bkPz8zdZavADOAMH5l4SGkW7kXXipKGd8cVAlFpMbLkTGqLbWUZUkQmrkGw1DzvSL_hisonAsFgBbqoHW6bnoC4JTB_-eb10--M_Uqnno2oGfWqr2Khuitvsy0","qi":"w1WEG5MvQKMY6kcFNBU9ilVV4ml5vEtQ1l6I0XgPGjB0SOlMYkQ0ORVlm9FN32VFfVVL8EDy4F3kYYdDsYLk-M2iA40Obeo1SnkkhpIQRpv3BvgZjaFTGlFFbExuqQFvlvLuIliicj8-CngF1giHX98xmwG89Y9NGSGa6M9M8AU"}'
        token   = b'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.kczCqhgqQ3l2i89EiGinGKNJRObSzLycj05UA0edrsjcq02HE-jgjWkz9W0PsHfmWIz8Jh_PHkuM3YttZWDIE-MLkwmrPlE3eR_D-8X5UlI7VySrWOJbavOCuOG6PWO6xvsY4Gt7SomBJx6GllQIcq2YTQ2Uxav-tGN_USxhft882NyBW3AltqE9I7eW0bkGuI62LvyHfRX72ikzOs4NNPhIaLYASi0exOIhX01iWaYWFYBO9LJZEgd43wnY6KxzXNai_2EBL6RK7Dc0NYemzli1BPB7-mqsnXGT1c3Yd2HKYEkS1qD9oDs0MfdJ17O-iO0hl9iMo3IXIRYGU0bdkw.CxYsLiNkLmHsPeDwyYBbgg.8Pcp-QPWWcU1MHBYet5agqUU5piLvoiWw_Phm9N3m3mgP5IbMoAI3B37UZpIUbfh23BIEyXECUxuhqQp3QpnBq3G0rpBoH6L_CZoF6S5qfE.7Am1ExTtiperJd2f-Tj88ZkXUp1Y8jX2QR6bP4iIrxU'
        payload = b'\x8b\xf2\xd9\x1d\x83\xfa\x99G\xc1\x11\x15\xaf\x8b]\xaf%\x80`ek\xe9\xa8\xff\x03\x82<\xa2\xc3\xdb\xaa\xb3`Q;\xd7\x06\xef\xe9\x9e/]\x96\x80)\x94\x1d\x85AU\x0b\xcaE\x9b87\xc8\xa6\xf6\x9b\xe0\xd7\xcaH\xde\xeb\xdc\xaf0/5'

        self._run_pki_decrypt_test(jwk, token, payload)


    def test_decrypt_rsa_oaep_0(self):
        jwk     = b'{"d":"MqLx5X5U7SWlseUpgXTPv6AcHVke2ujuhKB1haAmAR3LZcwysxNPFGLQUgwramWnNinWjTEf4e647l0L34pYJ4ZWXm0zkCX-TDduLkDdOW-4dJWQkgmSl9QIVOZJufTYND9X_qNyHKcRB0vN4lyGbxpnMeLN1v61TPo_PQY6C-F4GEO-1n3803XS1BMuKvgusJy2pRqSQ5IXRPm4UTuBBfrlCTI_MiE-IZ9SaJtNhOdKhc4bQp6jqj-QXQQAUDFkg1FzV07Tu20LVdZGTV5R4MdgN5SM6q2XZWV78MGx6Ci7oo8rQdlo4Zxx3Qqte_z9wQzVaQch4kFhnz1vLZE8mQ","dp":"KxZO-WPZ65IfxMtF0XlVqWXcn4M1hkRBRCPY3OKMR-ytvmfbxu0amF42jsfb-w0m--vFQYL_vXrnMhn8inA8dNXZjP37qpg4Ai00tMc4ww0FFgoHWikqmcKbelBZlnB78hatWxnHoRLUz96JIoRzgdGMPKFFXkxkKec8iFMOPpE","dq":"hzYo3w3tI1d-bzc5PXbUA7UgaWNa0JI_VnqoKwULgZN0u_xlp-IZkNzHhKORuLApYCdo5TdCEPZjb6bPM9tHtXCWv-JZ00Qnmz21T1JuBN8GdGZmeQIXi07VMOBBJcXuiKjvAOlz0xs7FRSO1YOa4GtEgypWkNdr4t0W855YOmk","e":"AQAB","kty":"RSA","n":"n0NYYJ5enn6N8egJBoDLggs53zZE3_GRxBsz4laDJ5H5bzGzy1fPDKpW66xHF8L71TWDe8BSy4KSfC9aPybhhGkXfNTEGTrLEBp39H0c0GEhaLAYRZ0CKs_BZx9l47NQU3CaSQtyhHr6MXkXaBQPbSuB____IzSmAJvWEl9_qdoXVaWNMyQo-0eRg0esM8lmCw5AaGfRpB3-iVKeNhbmObrSKAZOUH5HCQ8XvZA7knmXsODyVlQm1uv_bGQCP_2uwG5a0yoAgRTDCRQJWFolsZrhWpM0ujRK16Pl9XpOHOSnUdLf1TyMG1SdG9iyWjqGLhmGaRrnPgjvItQ9WmykMw","p":"z8E04cRk8U9RpYAf4dlCf_2z29Wan0yI-QO14XoR-iRE6twuFZA59oXH5D7iXxkzjTxxjyXX7dFg1CzgSl-os_OdNaHW4EfFbota5UDlOOoA9jB4BIey6Jet-UqolalBSqJrUL8cFGNBmGW5ze4IQTAHf-CyZK9vKts0k_T5QAc","q":"xD9c1sx3KDkRWkdqWiUtcxu_RMrPXeGiOxZdN0L-Xua9EBiu02zUDjt8hXRc0oHjZ6dtBxxDlN84plUxzfa-s_OBahUT103nWHxHPL3MoWelTsEHPgQbm2Q0kNosXptvtwT0BnFwc6b0w8yiS43XaBe0J_O35vO_J25fXWJAV3U","qi":"R3VFctqT99Xfd4yyYZtzLnmUbCPxu9elkbHhIbuO01wo386l4hkCArLHF0y1HS6aN7bhWAku1-jeiIeat92TxAVGJc1M5n5g2rqSXCwdw-AM1Q6sEOfra_X5I_yAs6z-Pan-hQSykBiIo6qREjY3Jxl67ZZdtOfczkhEqOKhMhQ"}'
        token   = b'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OMkUQNzkjpK2cC7AQBk_a5MNiT7o-XO6giPA4bkrVY31mv_PNxYLezYrg6bvHCLAIk4h_ucnFxOGQJGGdQegRrGlgrICDRjKQZW3Gf0yTuVCdQjWec_yL3EHrq3T7AJUE_moLu4AM6GAorcr9UPyAt4kxvi4NC51cS7IR7BrHkgT9w5gWo_6A2X8S-1efM6xvvFF6vgdOcTWgBdXAwOqnBCWxIS-ey8xQensbF271xwrWu1LkC053VJgofAlpLrWZ75uXI6k2deX3AnuMyXN-n2Ntp6CSpFEEfP8jIJVgpEAQ1B1RDOCEAMebDcC-NjjXsO2AgOhMRO1ACiKONRePg.n-I-uG6W4XyEndhN.82GHVSet-jk0_zdnsd0DWI7t7x9FLzAHZt--7Op1-KP3jAcQ1tc3-knLo7juqbn2W0xa3zLE_bsi4tS_aCGvZTQ4FQauiQ.kBeWWfO2lXSfyTYIhGYxnw'
        payload = b'\xf2\x8d\xfdh\x86?J\xdcu#\xffk@\xb3\x18\xb4\x03\x960\x04\xb6@\x19)\x8a\x84v!\xa9\xd9v\xf3\x81\x8c\xbdMf\xabA:Q"\x14\xd2\xdaI%.fI\x05\x91\x82\xaa\xc5\xf5)\x97\x03)d\xeb\x12\xde\xed\x18\xdb#\xcaQ'

        self._run_pki_decrypt_test(jwk, token, payload)


    def test_decrypt_rsa_oaep_1(self):
        jwk     = b'{"d":"bstM0W5ZwpbsVIXKcaRpUQwYq9LO--dXVIReNTpfqbsG3-o8VKU9bwkG84oZzsBrvqUkXy8e4WnBu3oD0hfPypZAcewReCTE20DiuqZa7Eg6tZugaOR2oH__uOEfCQWuMzLIfeBlq8M6p6KvrZA7Rw0bvWaHdTD0InVDOVK8QvwKGUDuIaahGoaAORF95oglO17QA2aLfeGh-h2zeoklN1HWWoNJulspT0hldFa9zFXKibu-TuWU7BrZCirCUsgvpfGvX-ZenTZG689mkVFao-RJoS-L-Mq_V33p97nMCT1_1DCU7AZSg6f6Ww0JYcfSC40adgWXMGmCnTGfs1iW6Q","dp":"FOzi93thPOA6-S5DylzxJbMiaxP9Gh9HwLeYU89hjvTaEIAkD6UveojPGdcbr2pYQit1ZewomhSM_sj4xm8_x8yHLlZ_tMGnq14HWHvgb0tz6tfvisi4IsWU0EbJE1kw1t4oAKCOQoTpw48KDVeH3ggtOtOC48Y8w5gQec7mhRs","dq":"KpdWF_ldQ5BU6nE98O93GXN4lKH-YverqNS5BctqHSUpwVP25cOY53zDZHH6afTefVh67sElHlqh9IItJp1aAL_Zcjven98wq1vWsko7y9j6-L1dBkwcht5QlEQITaXY1X0gUrlfOVRksct2mX73VuISX1WsBdiSGSLbkV-l_D8","e":"AQAB","kty":"RSA","n":"ugoSeaAuE7U4O9Ufi5vMCRz9O0cAIsc7nvNBAr7ZIbfT_rIKaI_JxYJk2xRUK-Gv8nfJxZhGhseZgM4bcZ0TVrYFRk2nviKw28rVCP42j_qWtoO4FwPQcKY79J53XNdyYfJADAWjSD9S6YLf-vZI9U-vQud2LePOBCDVIkOlu4GAJLLXWilr-UWc5HVywPgTjbii7BhfEwId8dBu0ny12JjE4PesphFaz54as7PVmQEwYyRxxCwxk4039WaHTBeh-ml3zij-s-FGnWlEoecnWe5f47tTh2JFJdvJh89VJDVQiXa5JKtyYlT3h0D6A1_u0WV3P0iRNwtdMEJo47TpvQ","p":"64L2eeHfY-fmvS-RPUYDMY8x0fGtAGmYVW_B5bJro0E-LhU3E7TfJZn9Cf0qXCYlZES9dLQvlEB_dxiOansbhfh7OVvBAurfSsTP-GdxWH5nl1w1Z0gvSE7DuDvZlOqZFXQ76bDnjz2xgHP1dyq950tdd3tOLgkUhgmWTlDRy2c","q":"yjlSbWDa8T91BoNH1apaHehowO7v-ZV6u5adbxWRb1wG3xMNOABroMZtyCAtB7h-Ap1RdiAVW0N_RSA_EswP6jkznfMSAQkBU7Xs77b2-CHOqR1t4gM0j5qmj2CVS4Ghu79XvdtZzCxmtw8Mdm5eSeEM4QJhb3VFCz0M224QDzs","qi":"MpccuHNtmcXRdnu2U7DMY-ZYE-ln3imUrAH1o0Lpc3vJCzCjG0BfxIko0H5Oxatc3P4ce1Z9_mCFAz2Q64nT7QhB3CdzIunTzxOmZIiWFBEX2KT3LisjZ2ouInWRu7RdB8_EuaMZ72VcJzY4T1OnRlkM2JsgD1UWt8rvfQlb5iM"}'
        token   = b'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.d0uv6anKNRXrYRnE_maQw31n-QvEQ_CcvffImVZx5R_inxQoVaBqcx4ZcS6YmXdrzuoC1C9kKq8tfcxFzExRzYF7VuSLa8DgoTmDjnJGrY9TAuNdNXqNm5sKuERd22HMIvQB3ZRboZ1ikJWQV-h8l_2ZCXQTelKFEjOviHvhLNk4y4YHVBj9-zNEZABrTf--_Ouo1wr9rj23p1yW0o__8i-mkKhy_eL3EJr4NaI5UiJsrfPXJlpDK-YqXuAk_QJwGj70d14NFUCGeJ7_JT9zBhgtPXsNTnIk4Z6APEO51EJWAjxjeZ132d3nOgTOq4UQvq8utA5UrzUhngkH9hV7rQ.jDwlodjJeU56vtog.fPm-tO0rVOhaSxDLp2wsqaxsO-nGgRuRJAQe7fqWhmcEyCGe6Yw-bXmF1SpXJ2eLUrpOM_H4vB8cveXpP6Lj1nvHzRSz1Q.R0gxpjzX-PrByeIEwc5tQw'
        payload = b'\xd6\xb8\xf9\x85\x93\x10\xe9\x88\xa3\xea\xb2\x9c\tqN\xc5\xc4\xcaV\x8a\x14 \x19c-\x84\xb9\xb5!1\x82"\xe2n\xd4^\xae\xce1zB\x0f\xd4$0P\xd8G\xf3\xbcq\xf5f\xb9r\x1e4\xd8=\x12\xf7\x10rO\xdb\xf7s\x85\xa4\x94'

        self._run_pki_decrypt_test(jwk, token, payload)


    def test_decrypt_rsa_oaep_2(self):
        jwk     = b'{"d":"KCwk6AxhOF3FhCJKkkE9UUQaGeN0_ijIb6sWLzGiC_o0KDnSa-8RALVpIJ7vz1-avuhu6oLzCqzy4d7-yOBBiK3HpUys1PSinhy2miiTUcjQ8MK6orv5DP1uf2E3EU6TRuMV94-n5nNmg9RwejhZTO9arHsr8T2hcZWkOozu1E6QC6Czhe06hahVIrXsxuuzrHxhcaaxJ2hrViInjlrmi3MWD_kNP9PTUXaXhxI_zo9LXNtQqAaZ5yARBpwSWu1EA9lZg7OeWqhjSDRNsdVOalyUemmdpzS-OX_t9vw6RC9bk0zt26vTXhOQCohZbr8dJcfgRpihhCVKXnlPaU2kAQ","dp":"aM_2rHNErGlg81iQc6g7byMwq_AMTI0UCBcWRsTCllLDTm9vymcGgH_Jw7UHLINABx7c-TXYWOH9cnkoSFnRBjoIlU37cmkF0KOfnMcLlejPOWBuxaR3WFds8NKdb3XqDuoicXDI1AbOBMOc4ct8F96cv9P0AxMlKWmGk54JRwE","dq":"w9nyo3CX-LKi-SfNJKdGniWo8bL9cVKK2eL0_JnWSO4Xjn5BSxaN5aDR-WO0GDKszzA9P4GPS9_acqFulDoIq_8QFIHTkfEqfnr18lE2XzwPbrVQuYeaFe69QGtS_yGtdfH6pPM-UUGa2qD9SUKi0R0kMw-1CuDH3FNvbhPPbls","e":"AQAB","kty":"RSA","n":"x1UR6bJXO_zbmTFwMdjqzkEIzKDtlFjSHJlPbwSFTZx0pn4c88d_6wlWy0gcMA52IADjXxYgNLgpOPFIQRsG1zThg2rgPqvzVqoI0QBqkf1DA_KTaRoffs7CYV7deJbOBbSUwGFdnjkAmvWx0zRSl9Bjxr30JWY8JalHy5zx6fAuV8lNbvDc6elpPpSThTVVCWCCrdZYusQh0_Zi3mpwyPoGP_yJEcwnbqEp3teFFF_FD7opsHdTFQFmSHBDPMQieICa102KPxt2PPLyWEfZolASmGsUl29cbL6KH94hXsKHGf-gRLCvqNszg0oYduVApapwfW8oKslwGo_gzewyNw","p":"-Q96TfzRQJ9Ulcoy-rJuMOwicm-vLVi0feThkmzfd5DaU2puNspboNx9OrBP6h3ksg6qpIE4m-LzO232b1SN1KmXXbxb7vZixt9w1jfYK44jSs95gNQMmBD6xGelbRO6sGYKk-AEM_nuECD8Odlw8D7dMj2-MxSuxLGfN4y5ikE","q":"zOLi8G6K5tFtE76YL-kYzl0gBbytZRntyN2bwlLLOjhm_uh9eVYmMS_L_1pgZcMsk-56tpVJiEHVQiNBDtkty9kyKrXm3iWz6w0Kmeobok0F4ioL74qWmyWveF3vfiuFwANWPz2RDnxl9uteEuMQiV4tGzxDLKjPzjmTgzcFbnc","qi":"F_NlMwJWvDDAnkXmRd4VGWWJ_GFwySrjvspuKTey21VZBntRUJ4ToVmdjw-WnDSLUD1X9kCAEqNbW33X_pE3cfegSWW_2wYy1Lf6_xndchtodOAHqrWD-4Os35KG9vPLHhR7siz8XDRh09vwlZFmQUu3p3kLWvIzxULOJJWUr5Y"}'
        token   = b'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.MbEH0JOqsun_UGRgx32POkYswB54J8ehSEEM-M7j6xwwxTiZFZjDKZXUrFoDVtrfEWJ4uTdf5tyH2KlKVihaosgagppDnZ2iPiMhz_MoSHYu1tcuIhWMOYeH6nJzZpRSQDjs7hFnTSQEBzCtjBiwrNl3sZy7xRbB698wM5SD9btTpywYbNlbYIyWd3bTyJXjF1Leedb-f_hDDJw15OFuzYuRsRndFurI78YozfYkSX8GovAJgdQ3tbhjATYMQU0A8EhCP_oO3NA-9QoWEVKsx71DAa8yGq0MCrfvoh47MxBl9TW27rgf_FAptzz7HTKnhmiYTofA9RH7Eu4Kc54n7Q.dPu98SLd8XZAaDd-.OmgVsVj66L_9tX3Dc0Qswi4kCOAEl-Po3fewOmbBX00kTFuSijJvGZnUJwxNCLujM99ruHRbSIK2BAi_BsD_k5viizvi8w.EybgB2q2Equ-LONVx--O-Q'
        payload = b'\xd0X\x87\xe0=Z\x0eI{\x11\x8b5`\x15\xa3\xf1T\xeeS\xfb\xd9\x9ep\x86\xe6?ww,yI\x10\x14\x89\xcb\xf8G|\xe9\x17j\xdc\xa7K\x16o3\xaf\xfa\xb7\xf6\x91\xe4\x9d$\xfb\xa6\x1b\x1f{\x89\xaf\x8a6-\x06\xae8&='

        self._run_pki_decrypt_test(jwk, token, payload)


    def test_decrypt_rsa_oaep256_0(self):
        jwk     = b'{"d":"RY7TVetqpt37AEKcIbh58cf_hBdw9GRt03UNB1ZFrR4ftSYKgHd4lB9YJjUwwF1weYP6oyzzp3yWkNXYVOwn-l19ynQaLQlw-_WTedVqnYVTeFENEv0z6K7Fu7oi5C-R1ekUW1qZFyvZacC-Om40xvDI9-ZcBvRZbBd8n_3T4MADHqWvcczK8Kdh7eobG6yQBpwtezKhgFSTGoN57kc3cjldPcT8yqvVZ-wTVKLDued2LZwfJg-y3HZ0p9d9_4qLzkkhMS5T_Z21fYd4zonnElwEs4Rcb7-BN7PDwBicXDT-DUhLSL4zLnPbC1RLD-lqnGckFtaSHuQE1VZWHwPjFQ","dp":"YUaryH3dhEdKLEOEpVIVC1AWHIBhajWnAuoCQY5Zm95gYwU86HiilDDLLp13bx8U8uambo-mRKAlMvRWCC3LAWfdIlj0GKRJiTOfiaXvlgNXk_d1k70YIh6OL_X0nNX4O_fMXHEL9GnogRDC4g6vUKOUdPkZAHkGrPDV4KXdB9c","dq":"a6Tso0YZ2d-03ukf2ssGmotuFilQzcV5_AelNxC7yHCW1hRAeZT5q1FGg5oVWztEL-HMmKU9Do1xeQaIAuz7sacQIBy3MkUnEd7tZZOiiXyc_Ko2BYEQpo9K3LG1hw45kgQS0PQ7E_iIi19KvJwbCEm2o1uYXELUONtiRbo9qF8","e":"AQAB","kty":"RSA","n":"vN1A0mmJeA6y3T1W4NXGAim8_dCPLk92oNcuo6UjMfwKxKKGR2ZvNiS4pdn_cZqtkZhWXgePc9UA2lz8U-u7C2VdR7_Rg8xZMO6W4F8T-zSVxqBbrgSBq1PzrlTbBRXRKGiO2Q3INZeUC_Gz5yTToCMgY0QkwOh9fw918fZY19GnyELUsOg5wBOKtWU_ZZJADqX41Qb45iTY_jVbf1OP4C5Hz28E0gsX6Ke8UOcXMJWEYuw8ifGMo_kI0-OfDr4hpUgDIAbqHkbCKpPjPP2MLw5FTcnW8NIwVHXrfQ993HiAXTnXwjnDfVK4MJvVOkzteie8jpVjemKX9vWUKzF18Q","p":"7tnxR2wy7k_XhUlfRyUwUxIwZy_3DCSmeJwx8nGcI1WCKDPyDTFz9N4-DLlmODWsXTkcBxRBTMNBxxmqgjCeq3_2RsjErJuXRyFWMIbTkDGyqzHNj8Ae_cqAwgNcyKKjs-wrH-KdwG2KdYFCwNtOtXmZSHUlsvafBcdhkRp_XnM","q":"ymyOAXl7UwnMDoeLu-I-_gn62uhrpleZ7-zaGETznd24ZoIFOpOnpljZwhTTCGaKKeYh6Q0f06a1JRZ2hh9a-rle721gqtw3BpbE_zE1bradMIp4AnYeIPOl2vBClfNL-hOtcYiEdOEwbbZH4gWJMiOPLhwaHqeGvLvdEpwtPQs","qi":"LeQVYq_zt3-SGCsWr2yZuIPeNv0uHXESOjQnBDzWW4bKkz3zrPSyBaxySNsMUAfeZuXKh6OojLGZlbn9dKqrRz9Nvk2jFKEATMtJPS_SwNmQkNNCZ0kRZHCAf1R4SH7V8R67Q_k0jrD8X3OiIVPkXJsbgAbpPKOGTJbdivJMZWA"}'
        token   = b'eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.QAVzKP7VMrh1XDfOchWqZgaY4r7bE5Zr4IoARKK_agRVoFhj5yoZFbFjOV6bGHN0BprMKoEBhENis6RoDLSZbdFvGikPXp9f8D4T9EnFF-xKw6QOeM1xFbiF6mSSqOeFm-mGLSc5aouCQPwpSnjhws7hlw6i2yBiXx7e-si6DTN2SbMgaKFjkNF8RWDEErJhF7rn8azm3x60F48bcadD3s832dFx4632POjTXVstsrd5iG7S23zgFoLvmfHECFUDeWvwXfVLjI_OGBRbSVM95qMzI6Tq1YsYwGWjHD7EuybD8KkxVlNDwcZ5imDieBIjTm6PQOPW4Y82Hs32yEreaQ.Axdt6sG3YKORKfPllENLbg.JDppcAfE0L-bIpNUa-SKWYqgbP41I2q1MTMgCdyQ_jy74Ny1ouqJHJ0L6c3xVJ5KZdNwwr8Ksgq1JCTF89sRys4-MrCypqRde9HgRvlZejQ.PM44seCEpsiUOodSfUF2TA'
        payload = b'w~\xab\xec\xfd\xf1o\xd5\xbbE\x9eF\x9b\r|\x16t\xad\x85vO1\xabz\xde_\xc8\xaa\xa0\x00\xda\xc3\x04\x08\xb1cEF\xc0.\xeac\x8b\x06\xc7[\x03\xfbt\x83\x8buB\xe9D\xcd\r\xe8\x18\xac\xa3fn\xa7\xfd\xde\xdc?\xfb\xf4'

        self._run_pki_decrypt_test(jwk, token, payload)


    def test_decrypt_rsa_oaep256_1(self):
        jwk     = b'{"d":"qCOTQnea951qlkNS1_T5u7K9VKrB6PweMkNPwltZ8RR0GPmcl-2Pw8fl8lmHmfWLROS7M1SnQkqJvBGeEzW64kq1vRDX8DHf_5wHM-v8jZpkIQKFNWAwHjW-5IJECXcq2P-iX0CSV_gWjv1a_6YOR6-bSof3bwfbnb5CviUPMYPAo_n8Qn7fZD00z39qi4QkGEugUoea7iI59lN0aiMDruIEq-iHP6tHTjJUDpjvuWTiQM8ClEVVRt6LCjN62xcSP_9Asgtx13eTBsJwonddogaiQOpFTFOy6qBk1cy22W8fTn7yN5dzMe0j1DEXSlCFriDDdZtc9Bd1IMI-pUOPQQ","dp":"XYimfWsI2dWl0KCPRmpuzjyYwviZ_kXuyTV5metsbhZmt2H6QDgK4e1KR80qDsKRX-SGvDXi637J3wDLk9mHy0JQoPPl_06v7SobyInT-mPErymcmEpMfEmQ9NNHpJKMF0rJ99uHQpLDYBcqYtuMvqgsmhZPAaqpOOKjLuNbAQ","dq":"Xyv5EKuwnK_0ETUC8k8la3M0o1IQd-UH8yJG98OpZY1X0Wex3JoU-jKQFEIdLIqyy94nNwQAV2NelFj9HLvZWe_-Cii9El49PdSmbbXbG0cE-NgKv6mSlSe-KbZbnyTL7NC7DXtgc-ZhzBfRKgBVbaFB-yeRFg8i8r8IP1JVKT0","e":"AQAB","kty":"RSA","n":"xSzOYagOXJaD7JrMQvz0-1bF-jqJF3QeTIFoCVvmg8Dh8phrA3IIKO6cNsiN6M7tbCbO_tFHbWySuW0KebNYmd2bm2_SH7m2u6oYpOv3SRhG2jPdQlOYsABHpz-lwgclvKyeROPDK4mXBfIHVXRHC9q-n8X2MU3SIGKnQRwkIGD7KOwmrFTeGrum7rWqhVMntfssXBIG-egxT1jDN5VJx2w6zMNiqYOxmWtYhAkXCcO7CZCFZxNOdax9QWI6sInc8MxCt1m57H3bHuiGH0dMHpUE6n9cXSudZA5JfSgnE3Uj7mA23xkxcAiG3hf21J4mGfN74DD4uPqv7PXoxbogNQ","p":"-W1gEC67YlFUZhD_vUSN7HO9VC5NPP_NfbYHfmK7mVziJMHZsIYdmpXLOD6E9SGrBo-8V0xTA684-hxxjGL0Yhr1CLa9Mzcon5rChw72ten9h9DKBRJiEZAjUQtL6kXXGj0DXGP9pZq6h5wb8A_UReJzW10YP-8dCXT1hBFvtkk","q":"yl7wmQDVPEPREGFQjfNjor7BxG9djOhVuDRg7oEilotnMSSIOKWJHCDxqY1wRyo7Cz712ffwFKE4PNzrTrDixPJvol1FMKjGcrjPq5R12vTH14IcSbGX2TasQy73DN6X_z3FU_gb1fY6xwJYLN1vE3_7-7oZNsezqqnqksn06o0","qi":"JG2Sya7oyMUpgSK8fv9brDhJaBEyvj6Y-UwEkx7dpkuzApf1H8gqzep05gEdpMUQILn7wxMP1Ti5D3J9HS0s705HumYc6ElKXsdd5TMZJTnhRsdZBbZIrEaO-L8TlKx8oqq5J5Izwo24cxhZ33GX-uMyvPzydV_wCYKnd4TwNsY"}'
        token   = b'eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.qtpV-CP8F5hgwxsNyZgKYMB9ZCgkn8uXPwtLsfSoB-dXBJSawkpldHr_bGsADl0n3Woc-slxCAAo9GhBcjvNJyd4ZOY6_SCdvY6BIfKlDOfAU01vVDM2anuyyPBGe50wD0eRfcuDjQjj8aQEdZ_tpbHN8iCKauY5fwd85FuknyH7jPbyt9cyLIcPdVs8asBoVvWj_SL83NfNe4stsl2TeKoKAICA-peHHLIN4ly_T9HcwxJ3hJ4V9Dm9tQc3xS9aBCMGOs8ydfAZLfuJH-ajOHXKubsSK2-KT-br0A-lhwlC79GNKNMZBrz84UUcpMYS-g8FiWImVZOEj44BQY1K4A.qpf6bZkfk8DI-jhmxG5j5A.OWR88jmO5yd07YYD1hyovNxXIMwi1oeRCcfgwKietgUsM4UmCoZjooYOBoyXVJciHcu3TkBE-NgP2lapbNYTi8luOkphgrMhVfKrSW3cbOQ.cq2XmAJrhszLXKi0LhBkPQ'
        payload = b'|\xb7\x00\x97\xbc\xe9\xaa\xf9\xde[W\xed\x020\x0cb\xdc\x197\x94N\x91G\xb9W\xcc\xec\xad2\x1f!\xb53q\xed\x04\xf2\xc3p\nE\xad\xb2\xaf\x1d\xc5\x1c\xb8\x10\x84*\xeay\x9f\x9b\xc8B\x98"\x9bI\xf4\x82\xa2\x93<\xe7|\xff\x9d'

        self._run_pki_decrypt_test(jwk, token, payload)


    def test_decrypt_rsa_oaep256_2(self):
        jwk     = b'{"d":"lL5CbQBnrZ_Ts33cPF8uR0h5HB5TKqcdzafyyWp11WBhjbRAaZgoQm6LwDDpfs0N5AqRZwxAB_Ksj1COtm-XmnDcXTDEil8WAA3HYU0b20io4HnNWnG31eKhLN-u24x4feB7XDWRVKRMxQ3T4sqK4ElCptRqiTP22FyRa_WNmG0WiujmeGy4IXDtN2RE2RJaBfDrINmjsjr-C0nYWUr7jMItzPj56THRLrioHXeeI5Gu37OJFXW0OweOtGi9o7T9_tb6iE8qy3mfeFa2nbxjAmvyeDxzBUeAWnCbZzfLNkrNMOsDGvShfnJJVWIJSlttUHkX4JrEJenpq2CzmsXiAQ","dp":"Gwb1QM73jg4RNdVUOWLHqJA_yV67FXpTFFKzdo5yzMn43TW9pLZEh5KEnT1qx5wzkSSMSSbiN3JSh4_lBbOF-6pfnvQXYd0epXTCaZRQ33WM4-vhh6krVQL2thk-VKu47QOmuOz3hEWdfzqOL10zxSSeB9oAYPo7DtZO_K67k-k","dq":"MNIpiYaJs_p7KRCjV9f1Q5zGe-lOvpJM9E7Cv1H1Q4lqwIvjTsuRmOecWvlcKNJpdpb8OQgdcs7vtJzEug6cy1dP4RtHmsIWE8Vpsx8xcxP_udTKcVO5TxQvBIvDOuhLQkCSbyNttTDJg2S-shaAyvLuATbnP81Tqt2xQMzXhwE","e":"AQAB","kty":"RSA","n":"umaCboQpZy6I2ri2B-_g8BbzQsqG8ZDQhCg9c0B6ztRf1khovrdy4GpuONrq_l9jwNDpQCEWJD81UAupCcbsUR_JtqCyFIc-gGXa12_BnlhMhqsD2AgeEtu3ud3wPmZRZdF-HcbSoNAHpJxu2RxCBQXnOKqNd5DSguH_K6ALMK6kKM5_F5XuSYRJWee4V34faZ3T1yC9mqtRK9yh_OVUuR-ZD9NGVqAHrGxWnww2dsdcWunh2FHw1aMe2Oi9HXPuut9DIrLUKynnCMXx5ZPpwiifLatgghjBZ01ocVz3zFc1lXAovpjUoZEFgzfGoZ0ZRFectDzMP0KbC8yDMaXyxQ","p":"67sNal-LPmcjXGpeH_3a6OXHOhKMpaB8yRJ1YQcQiCtBugqXN4fYIgmLvu2I7Vz7ev7j6pNuq3UQE7TuIjl_u99nr3MH5xP7dEs4tB4Qnk1rGOWt8chdJx9EPmoKJl1E6gK3c3xenqrRWmxA7yYPert93pzdayLSCtAGGSJIdEU","q":"ym2XLAXiC4jpBrO4vmSx1E2EdxKKDlWjh0zJtga_RWV1dJ_S0rqnSK0xLoLq4gN4fCLmcUAlO_cZrh5n9jTpQnB0fbwuWsq6OUMb9q9yzelvbahqFpSYjO7Ew_Tab2xjjUMYtgNAw15nZo9GTkfDpLZzlGfsae8EgXaoGBHBrIE","qi":"uWlU_g5xSiOB7Zfsih1CoqyF5Rfq1ez4Hayi1aBt4Ff2v0ZEC2hDlB9lhkbsalf1IFSD4SumikyI9F3sJ_qj5Wh7wq9oO6_RixuzdNk2uXgiE_AA5T5iZq7IFnMttuOJbtJEVYSJyCj6z5nTZFCCWCnVHnMzNSQL_CBeFdbmsU0"}'
        token   = b'eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.eoHxVGnoGWS2j4zpBKtLEe9m-fCOXX7_CYp9qrvlnEu8MrCRRqLJFZU1SOfQhK_mIuKiFIWtAyTARo_HWkAkj70ukV9U41H2q5rrd8aHQ2PjPh2wGS4PEL4NgLfAnsuVX7XIRvXAUpUTdP5IBl84WNNiCnFjPCwOcPBUX3plcFNB4j6NpDPSpOldFPHOlg-D-07JW-WT2YEmvsPwTcEgTOF4T1haIg8FPZamtmpyEtlbMGv5PVKxpKBejZgA--gtMkFZBf2Bfb7yUlzsg6Gm4EYjau_SLO8VVkmKaefKWvCZI7gBRP-QiQ3qwNvzV0Vo6bdeIQAMBFz-oPXciRcMBg.OcT2o1oOQIaF8qMLpORFDA.yA0uz9YmWFb6DvdabXBSJOpZKYsBt5hWhhT4C8VCgoJ9dd3eThHEopncPGn10G-gBwfbgYIa5-QIFAfmK5L1_SmtbEZxo8RMQjvdZ08_40o.g-xyejvNktHPZVWSpDJafA'
        payload = b"9\xf2\xcc-\xc3\xcbV\xdf78\xf1\xc7\x14\xa9\xd7]>|\x8b\xec\xd9b.j\xd2\xe1w\xec1\x0cj\xcf\xec\xb7\xed\xe8\xbf\xc1ky\x81\x1d\xcb\xe6p\xb9\xd7'K\x03[{\x85\xa0%\x99&\x976\x94\xd9\xe1\xcd\x1e\xf4\xaf\xa8\x1f\xff\xec"

        self._run_pki_decrypt_test(jwk, token, payload)


    def test_decrypt_dir_0(self):
        jwk     = b'{"k":"Zkk0o3iiFxP41q4JHgb9I7IRI3dA4cUv9gOaaRHL4yE","kty":"oct"}'
        token   = b'eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..qN6UQump3Qgd57N7_E86sg.EPGLr7QJNdu6Rpl5d0TcT92HbTnYi-tl1FWLIWVa0w4gkmRZIPV5PoVhaAngT7N9j7FABTI7I8Xk8bRt3ZuF4L5ko8gPjAPB4yyISGPpdkM.g8Hwa6YtsZ1PlanQ99rdJA'
        payload = b'\xbf\xfa7\xf0\xc6_\x04\xfa\x0fI\x99\x17\xd5t\x91\xd3\x80\x99\x89s\xb3\xd2\x14+\xfeS\xe8\x11\xdb=\xd0\xc0x\x03\xb1\xbe\xc2}\xa4e\x8a\xdf\xf5\xf3\x13\xc53*\xc28\x18\tM\xefC\x85\xf1=\x1d\x1d:\xc8&\x865v \xc6N8'

        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_dir_1(self):
        jwk     = b'{"k":"R-y4Ogy5tyqbhuDV2_IYrd8cwsuYKCgq5IBDqaSDy0ZxpNf_LyRQpMvyfBSNfVDm","kty":"oct"}'
        token   = b'eyJhbGciOiJkaXIiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0..3BkkNhU-29BpcNXNnwW07g.Ieeq2IdyTqiOORMDSkZRBPwVEmEkbJ2ckEx-chUqFTNKZiJgMavlqYuWhqk8XGWG68oX0Eg3zyRRKyKn9fpCTCbg3yUeRZLGZbd9ZWatJqc.ZIKNdQlIwI9OzOsOKV-EOP3KF-X3NWVk'
        payload = b"(\xfe\xe9\x99`3F#\x18\x05[\xe3h;\nFN\xc9\xba&j\xc4\x16^\xfb$\x02g:\x18\x95\xf6\xc5m\xa7\x98\xf9\x94R\x86\x8e\x8d\xec<%\x9cu\x15\xbf'm\x86^\x07f\x01\x9fG~\xa2\xe2Zi\xf9\xa7B\x8c\xdd\x81f"

        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_dir_2(self):
        jwk     = b'{"k":"Q9WedwyRKX4hW-g9pyTK3_9Z9QSMkF0TGfgjCjL-FiPEG_enkAUhIvbsmNBJnY-3ulgPJgy_lK8-qqTQ1iJg2w","kty":"oct"}'
        token   = b'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0..3zzrQY_-T5Fwgo_xo_Rqtw.OF0Fr2RXqggJvS2r9kFXrLH_l1QUzy4Dk-auCYEsQByJmb1sdhPX5BbOl5H_m8m_8YUdEFhMq_KADrtCTtyE77WLya_Vxli-2ojDeU--_a8.EB8qhA1z2dxxCjBt8K5fVVrckZAtUByc1wv3v3sBSwQ'
        payload = b"s'\x12L@J\x0b9\x95r\xa1\xb3\xf6\x90<\xc6\x13=<\x94\xf9\x86.\xeb<<G\xd7-\x94\x0e5\x88\xa5DS\xff\xbc\xa0\xd84\xb18\xc1\xcf\xe6\xd7\xb4l\x9e<\xa3\xa4\xa6G\xdco(\xceB{\xbar}j\x85\x94&\x96W"

        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_a128_gcmkw_0(self):
        jwk     = b'{"k":"64AJJ5sxM_zZa5RWL51kkQ","kty":"oct"}'
        token   = b'eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiI0LWFIT1Z2dlQzalZmWkpvIiwidGFnIjoiUGN1MXlSc0xHZmNOVlVpeG9XdmZIZyJ9.8nD1yJL7ASBAL1XQING6-A.VBrI56K0AOyuOvI9.s3e99ycFq7BjRweF-OVLRYd1EBkELFKtlRJGACRlyDTDYGOOpj8EJFFAWpujoIHPKHAluVbXFc6lKWyyyaAQv5UaVuPMAg.v7sBQO_y5vgXarXl0qi3SA'
        payload = b'xu\x91\xa3\x17\xde\xebH\x9d\xaa6\xb6\x82\xf3z2\xb6\xfc\x88\xa1Z\x15\x85\x9cFw\x88\xa0z\xd2p\xbc\xb9K\x10\xb76\xc2\xee)Z\xdb\x82\xc8\xff\x91$&\xb6\x0c\xa3\xfc\x1f\xb9r\xf4\xfe]\xe5\x00\xcc\x1bL> \xe1\xdf\xd5{\x82'

        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_a128_gcmkw_1(self):
        jwk     = b'{"k":"Z0WxHMKtVho1RXKiTSnmQw","kty":"oct"}'
        token   = b'eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiI0RFlUdER2dHdJc2VHeDJ6IiwidGFnIjoiejlqTGtURnUyS0xtczlpZ2Y5WTRkUSJ9.i57tTKm1sM3BAbg3owg7cg.dJKwmr4mE5jQsNp0.-09LcdFSMmKS7KV7m18Q375Z36PXQZkCnsCj7SGhnbnbS5RrXitUAi0i0M_FRADSFSK7XZGF0PSXFRvzJLtmsbzKUiItcg.gik0QyyNfhZu4AErF0sjGg'
        payload = b'\xf7-\xb3\xca\xc6X\x94&\x81\xff\xfb\xcd\x9a\x95\x10"h\x11\xb9\xdbA\xbb\x80\x98\x9e\xc7VC\xd8B\xf1m\x16\xael\x97VGM\xcc\xcd\x1a\xb1K\x7f\\\xcfk\x1b!9i\x1e\x85\x8b\xdc}\xb3\x12q7q\x0fD\x17\x02\xa9E\xb8\xd3'

        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_a128_gcmkw_2(self):
        jwk     = b'{"k":"Xb8NDy4qeng61oksfPgigg","kty":"oct"}'
        token   = b'eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiJSaGZwNUlMNmVMZWpnNjRIIiwidGFnIjoiOTN5S0F6YTBTS0RpbmpoWExzVEhyUSJ9.eGRw9Dpht9NIOlF8sys82w.q-Qn_CCLxzNq8v2R.tz5TmhdzMyhB8DDplQp9r3YQurcGtABlLgYXwAbRpknETRMLDud6uceCJox5UKi0HI7xVGDkqPczakb8qxyGJUWSBne_FQ.jl34g6VDb6m5YJkKggI9cw'
        payload = b'\xe6X\xbb\x83\xbfp\xbdU\xb4/e_Q\xd2\x18(\x05a\x80yva\x07i\x93\x1a<\x0b\x04&T\x8b\xd5)Q7\x11d\xf6XL+\x7fq\x95\xd0\tU\xcf\xa6E\xddZ\xcb\xcadL^\xcb<S\x19/\xcf\x82\xd5T\x1c\x16\x08'

        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_a192_gcmkw_0(self):
        jwk     = b'{"k":"2ejtUmIuVK7QEoJ0-QB6PRSml5Cb5lt5","kty":"oct"}'
        token   = b'eyJhbGciOiJBMTkyR0NNS1ciLCJlbmMiOiJBMTkyR0NNIiwiaXYiOiJZZm1ZSTY5NE9zbm8xLVBYIiwidGFnIjoiQk5JeFdtcGdhekhrZ1RkVjVaa0FMdyJ9.puvaO0b6N36vJCbPWj4IewTXchc4AtGy.2Joax1qX7li_1RHH.0IOgNLkk4kZmZTRWI8hxRoIHJSk5oyHYgFvIF0FNVgEM8-2LKGW_Wq6c5DT7Y1jOwjkm7x_pM_zhptlymu6fy_jZnXeDig.238OSJU1EtcwPNSppABJiA'
        payload = b"\xcc\xc60n\xb2Q\xa5\xb8\x80\xca\x1f:5~\xd7\x17\x12\x1f\x14D<\x9f\xd8\x16\xf0\xdc_\x18\xdd\x94\x1a'\xa9\x198G\xd6#\xc8$r\x94\n\x87\xe2\x1c\n\r\x1f\xb8C\x90\xcc\x06\x14\x08_\x19\xce\xc5m\xaa\x93vX\r:C-\x9a"

        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_a192_gcmkw_1(self):
        jwk     = b'{"k":"DhnDAbB6jZ5XH1uACzeSD8HtFl3mE1so","kty":"oct"}'
        token   = b'eyJhbGciOiJBMTkyR0NNS1ciLCJlbmMiOiJBMTkyR0NNIiwiaXYiOiJUQUwzZHdiTWZJNUhUTWllIiwidGFnIjoiT1o3MnA4OW1PdEExQnVINXNtOFVOQSJ9.K-iclY5meKzh3766Kf_yrPsTNSqUXSb5.F5gaF6V0fVjNCZL3.RHX10hZyurAyQ4iAJRiI0YNrEmqYDFROoY1PV91QkBzA6lVGKi1FON5twL7ui6g70OBh-7TQ5hxgvkddq3B7Nw1P4sengQ.5rOgehK_oX5mrEqRftgB8w'
        payload = b'\n3\xab\x83\x96\xaf\xec{\xb7\xa1\xb3.`\xb4\xa3\xe0\xaf/\xf1\xf8\x0b\xc7wY\x8fO\x19b\x0bf\xb2\xe9$\xa3\xe0\x01*\x9dv\x0b\x104\x1b\x9f\xcf;-\x0cS\xed\nJ\xa1[\x07\x1a\xff!\xa4;\x88\xbd\x8b\t\xa6\xa7\xbd\xdd(e'

        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_a192_gcmkw_2(self):
        jwk     = b'{"k":"Pt9XfVYmj9vucsMTI-56G6m6_SOv1nUB","kty":"oct"}'
        token   = b'eyJhbGciOiJBMTkyR0NNS1ciLCJlbmMiOiJBMTkyR0NNIiwiaXYiOiI0VGZZMUNRd2ZEcDJpMUtpIiwidGFnIjoiLV9Cc0dkeGZwcmZscGM4a3hVbkhfdyJ9.4soQ8JaKIivmIXqk7goWiAAPhM0Bg9TG.ZTTjit42PyPZwbzx.Tw0C-HuLYqnXcKIMHmM52QCvXYVeNAOo0DjLJwU-wFCdbV7zgXORs9HoHjhaqdLNHcHkOiry1MikJQTlzKThX_7D0uStnQ.v3mLOclx3F_o0bNOCKSY4Q'
        payload = b'\x89$\x9e\xe9\x86\xf6\xd9g\xc2w\xd7\xc0B"P\xaf\xa5\xc5\xb7\x86\xd3\xe2\xb0x\xef\x87+\x8b~!\xf1\xf9l&\xf45\xddj=\xdb\x8fI\x90\xdb\xf0\x15q\x85\xfc\xbb\x90\xba\x99\x02:\xc1\xb2\xd1\xa7\x12\x1c\x87{\xb6\xeb1\x8e\xb9z\x8c'
        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_a256_gcmkw_0(self):
        jwk     = b'{"k":"bcGKLGx8r2QekSI6v1xT-X6PXD4ez_R0UgJBaCR5tPs","kty":"oct"}'
        token   = b'eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2R0NNIiwiaXYiOiJuWnJOakNmOWY3cnZjVzJXIiwidGFnIjoiRFItMlZQalQyNnRVR0tWdldFMTNuQSJ9.sTuZVY-VdIFkMwv7qBMm2AkZ-E0rQIOmtbn_qph8g7c.v-XMKhl0LiFpoJJ-.RLbnFkU3J9rSeEBLKdHDKGEpypMqdr1mhK9IUplld7NjzyqeQ_Jryk5R9X3NUpXLVp12ULEKybtFp8XcfEjn9ZyJb1OAJA.PMEVMoL5i1aBDwG1W1irlw'
        payload = b"\x0b\xae/\x1ap}\xd3\xcf\xb3\x9e\xd8\xc0\xd4\xef$\\\x9d\x83\x86\xba\xd9\xc3l\xd8\x90@\xeb|\xaf\x81\t{\x98\xe9K\x01\xa3\xbfp\xa7S\xb2\x7f\xe1\xbf\xb8\x8fr1\x8f\xd6*'xL\xa9\x1d\x83l\xa1\xbe\xdfX\xdft\xf1SA\x98E"
        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_a256_gcmkw_1(self):
        jwk     = b'{"k":"Ooov5OuVppeurDh3IWbK9pqp6XD8GIWpTiQYjjxi3gI","kty":"oct"}'
        token   = b'eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2R0NNIiwiaXYiOiJ1NkFtS0p3ZTFEQjBLTUlHIiwidGFnIjoiWlVmQlVKV2VKSGZ0a1NuWEdyWGk5USJ9.R9yuY3h-VKdzKM4J3Q165ZdW1fEWWL6cmcgvTvsWzqE.4Dbz3VwuC1Nx5uZp.8LN5GhhwERZoA2MHS0dxj7lpDZeToKnLMnrmjeTFqSJu_pDkxo9zX0Z1CT0HbusEdQYjZStKUEXNu0LtBCi9Az7OgAY_9g.khA_wnDWpSATWmW3jvplKg'
        payload = b'\xbfE}K\x07\x85j\x8d\x014$\xe3\x8e\xb0\xd7\x01\x90n\x937\x1e\x0bSQ\xa4|G\xe4\x9d\xff\x14s\x13\xa6\xc6\xd1[\xad\xec\x8f}\xf01\xd7-\x8bgJ\\\t\x1f\x88[\x1d\xe2\xb3\xdb\xef\xb8\xa3\xd3\xf1\xfe5\x93\xb7E\x01\xcc\xba'
        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_a256_gcmkw_2(self):
        jwk     = b'{"k":"yKqtl17_GtAhcwg5TpmCcpO3q0UxlCCHvjm7LYScP94","kty":"oct"}'
        token   = b'eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2R0NNIiwiaXYiOiI3d3VybUN6b2phaGJTcjdXIiwidGFnIjoiTkxWWjU3c2FMMmIzZDNDSFNuZlBYQSJ9.IA6Q0IplgyB54NvASl0mLPsvZG1eJI_b-dUrgpEi_0U.jR8OGI6OnPp001L4.rWPGTQbq_FuZ8g-tKtCSseH1H022XPIIAJFJwZiRkbscoJVl3mCnt3fiXoiBr0vDMB8wSFMyyINgXlf7TD2HDgg1nOxB1g.hHV56Nx0eYjpAkjsoi-JjQ'
        payload = b'\xb8\x86i\xd3\xe7\xe5V<m(\x07\xcck;\xf4\x9f\xef\x8f\xa7w\xf3\xc1\xe9\xf7\rt\x8a\xe5\xb7\xado\xd96W\x00\xa7\xe3\x15\xd0)\xbaG\xb3\xd2B3\xc0\x9f\x16\x0f\x8a\xaf\xbc\x8a\xadE\xf8\x1d-\x8al\x83\x83\xd1nj;3\xba\x99'
        self._run_oct_decrypt_test(jwk, token, payload)


    def test_decrypt_pbes2_hs256_a128kw_0(self):
        jwk     = b'ff03e597700749a727521630'
        token   = b'eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwicDJjIjo4MTkyLCJwMnMiOiJsOXBTbUhDUm9FWDFObGViNGJENGZnIn0.YNCPsZynjG38Fi21UB75VNdPC2AniuIwmHlfXDKC9SlCRr3IyAfpwA.pl4VallSXSxzwj3lNIT7Ww.iDQEq4PFpF4OkmKc7O9pBg4gHqW3IlelIglOcOskmQqK_pVSS-Eih0RhhWEgvzf9a4mxGJ03F9tvpjhkYrtMdyruJ85o5lbjI9dQYvyOK80.OEZmJaiFxP1W-eQZoaNlGQ'
        payload = b'\xbb\xe7|_\x89"N\xb9\x9f\x92[\xc7\xa6\xaf]<\xc5\x94\xe8_\x06\xcf_\xd2{<u\xff4C\x0c\x95\xbe\xfa\x07\xbdI\xd8\xe7\xcb \xe2\x12\xbf\x175\\W\xfe.\xb8\xe1\x04\x82\xf3ol\xd8L\x8f\xb0\x90\x90Bl\'\xe0\xff-\xd9'
        self._run_jwk_decrypt_test(jwk, token, payload)


    def test_decrypt_pbes2_hs256_a128kw_1(self):
        jwk     = b'f146b8c018abeb6294a839b6'
        token   = b'eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwicDJjIjo4MTkyLCJwMnMiOiJIeHVfQVBuVmJKTzR5M0taSHFVR2x3In0.Vh9ChJcBeESgq6KMFJnaKlXkhHtQSQM0UVKEOJiZ7V4iVWSEKbE6BA.3StM05Db9qiV0nBGiO6FXg.CPtIhJ0UQVTG5_oS7q2QES9GSVdVveI-5Pz1v3z7PGioj9QjPzuAmIKZ-Kb2PT-kwqdvXJyfrdJtoTmFM0MGzAq8I2BV-YMlIPfF7lJ375o.YkJS4L2qtamkLpatROTkDA'
        payload = b'VZ\r\x08\xd1"\xa1\x16BAe\x0c\xde\tTy3\xab\x07(I\xb1,\x18\xc9d>\xec\xa2\x84\xd8%_\x87\xbd\xe7D\xa7P\xc4\x85\'Vm\x12Q\xfa\x16\xf2\xe9\x18Di\xfa^\x00\xa8QK\xc5\x98g]\xd9\xe9^1\x10X\x06'
        self._run_jwk_decrypt_test(jwk, token, payload)


    def test_decrypt_pbes2_hs256_a128kw_2(self):
        jwk     = b'8f3a87f92af840794186fc82'
        token   = b'eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwicDJjIjo4MTkyLCJwMnMiOiJoNHlRRFMtdFNacXZmYUdOdllrUm1nIn0.HwgzmEdhhk33l5Sz9PoxGK1PqpyUl1XOtvnT6eJurbvrKpxJ40Aoew.GD3Vu5bdKhXneN5kzK0AhQ.RKxAMkMdO6vAOAuhUZkS-CaUxZB7Tdfrq2IRDkHu4hnOLqu8ovtD5RfdNNv1y-QX-Xa6C6-BOUFACsLM9mvGWmF5I0ngYkJCQuuByuDv4LU.3f0N6U9t9UG1I1ApYkyndQ'
        payload = b'\x12\xe3\xd9$\x10\xf5W\x9e\x80\xb1o5\xeeM\xe3%\xb4\xb4\x8c\x859\tz8\xb9\xe4\xcc\xcd\xb92\xfe\xc7PW\x00Sk\x12\xdb\x91^\x1bk\xfb\x10**K\xdc\xff\x07~\xf7\xe6$6\x8a?\xdcag\r\xec\x80D\xfd\xbd\xe8a\xe6'
        self._run_jwk_decrypt_test(jwk, token, payload)


    def test_decrypt_pbes2_hs384_a192kw_0(self):
        jwk     = b'34955f0cc657e36a477c2e77'
        token   = b'eyJhbGciOiJQQkVTMi1IUzM4NCtBMTkyS1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0IiwicDJjIjo4MTkyLCJwMnMiOiJsOGtXeTZwNW9kZXVVWXZTVmFHTC13In0.9yRJsXxkl3Zn62_Ewt0Y22wlH5b-fT0b2CB2Iec_qUvukAvb3ZFcS7WwFRFcPKLw5UH9zRbqQHc._B3_R6_ZYeJvgLInCyGHGA.i2RcvQ7sJZoqVq9u3ygDTVd4zyM1CvyqXvp7T2wKUpcq1cM_eswQ1pFAq6-SITrHotkaYAw2sLhcIXC_fdxLW5P4ezmzyx-wlhK0hit7_Z4.FCaouqRo87sZNOC_OpspsO3w9ygBpjud'
        payload = b':\xf6\x10%\xfb\xaf\r\x0b]\xc5r\xef\xa0\x1b\xb3\x07ft\xd5\x07\xca\xc8u~<\xd1A\x9f\x9e\xc7j\xc0\x86\x1e\x9d\xb759\x83\x1cW\xae\x99P\xd1\xe6\xe9\xcd\xb4c\x17S\x98\xaa\x89/6\x94XX\xc6n\xcf\xd5TP\x8fpLX'
        self._run_jwk_decrypt_test(jwk, token, payload)


    def test_decrypt_pbes2_hs384_a192kw_1(self):
        jwk     = b'77d6fca85b92c8c96efa785a'
        token   = b'eyJhbGciOiJQQkVTMi1IUzM4NCtBMTkyS1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0IiwicDJjIjo4MTkyLCJwMnMiOiJtN2VxZklTMnR0ZXdyODhyUkJESUdBIn0.ZkBPm4QCCmfKXESeu5jT7ouJVpX7jQoBxAp-HxiJkk0MVI74wSrb4EPO3r37iS1wedlGdL70Ta4.HGh93Zbh8F9WcaNTP1J5lg.wI7fO1kmWZRdUZB41Ct656q3dnBQNnTvm2HupoLYzeLEJccrsu2I54ic9zXU2VsvSBxd_gM4KigGwV2_c_4516PTFiG1ik4OGMRECH6_gJI.NzidaguvU6ASgw97oWoc50zaRLF35pG1'
        payload = b'\r<\x9f\x9d\xddk\xda\xa5G"c\xf3j\xed\x86@\xa1^.\x0fY\xea\x05\x059i\x91\xc6\xe2\xac\xdcG\xda\xa0\xa3\x07\x00\xe5\xd1\xdc\xad\x0b\x18\x8d\xb3\x8f\xf8/"\xb3v\xc8 1)\xc7\x83\n\xa9\xa5e\x02\xc89k\xd6\xe9\xd7en'
        self._run_jwk_decrypt_test(jwk, token, payload)


    def test_decrypt_pbes2_hs384_a192kw_2(self):
        jwk     = b'a258538c59f687908ddf0aee'
        token   = b'eyJhbGciOiJQQkVTMi1IUzM4NCtBMTkyS1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0IiwicDJjIjo4MTkyLCJwMnMiOiJYMVNMTDg1TTVsS3B5ZmdVTmpOUWlRIn0.QZfPMz_d0mbBOowfZ5wQni8yrmjdEXTMofwjU2wEEsj2NSLWVrumQISsB86MAU-zpxNhnVO51RE.qbjZLC4tjHxUvs_Cd2-3-w.pqsm3u-2okQhLAv-U6_uiHHoHe1N2RBrLwJdIrFHGWgfCv9QkdQw4uM5XoXCs3ssr6ST-ViSH2-TOv6Qg2KPtYwct763iZWQB6P2vOqwC7g._z22e-k7q0y2ro4LUB6tUBTYLk4RatBl'
        payload = b'*\xdc\xca\x81\xcc\xdb\xa7\xd8,\xcd\xa5\x1c\xd1\x12_\x1e\xea&\xae\xb2GY\xdc\xde\x0bS\xbc\xe5MC\x82Z\x06\x174\x06F\x02\xc4\xdfb\xadH~\xf6:Y\xd5pq\xa2\x01\xb5k\xad\x05\x8e\x1f\xf7\x90\xa4\xdd\x83\x07\xf1\xabY\x19\xf5\x8c'
        self._run_jwk_decrypt_test(jwk, token, payload)


    def test_decrypt_pbes2_hs512_a256kw_0(self):
        jwk     = b'346cb23c0569ac06fccef20b'
        token   = b'eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwicDJjIjo4MTkyLCJwMnMiOiJxWm5IQ1A3MTBENjd0aXNtUjFvbVdBIn0._ljPYApGhKa2QUyoeUPgA_xDYM8pXKbpCyDx2-fgeVTrloKBqMTjxWLbObrM-s63u0JIomXkSEaBJg0DFYIJHN6mPZapsGdD.OWpkzDA9QDiXKRbeie3Qsw.S76pfIBqNEQykytg2uKivsEYxNYMI8Ffoc7R3m2k_zzr4j_9poNn6aVQssHOOqfLbaugqa4iR80CI0q-FLX75P6HJ2ZWHolZflzcScpMSaI.XbdUflU-YY63FlGWQtRxYIBm9xOzoE_9tIDswvPb6ys'
        payload = b'\xde\xba\xda7\xc75\xe3\x91\x1bc~\xa0\xec\xa3\xdf\\)\x9e\xe6927\xc0 \xf0\xd4W\xa8\x86\t\x18\x7f\xe4\x96\x12\x8ep\xdc\xd8^\x040\x18\r\xbe\xe8\xb4H\x0eo\xf1I\xbc=\xd4\xf9Fr\xdd\xc9\xdeq\xf7\x8b\xea\xcd\x97\x1b#s'
        self._run_jwk_decrypt_test(jwk, token, payload)


    def test_decrypt_pbes2_hs512_a256kw_1(self):
        jwk     = b'cc3a74d26359ed064bfd8221'
        token   = b'eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwicDJjIjo4MTkyLCJwMnMiOiItVW04d0J0WU9kbWdjNFNoalRfRTdnIn0.KP2PGtbLG7ayFl_sEOnze2qWZmRqW9W8KN9_iCgtjt-6_0jXWDTURDOzv-4BSCbm2lt708QmmvMyozvKovPA5ev_Qxg075pC.IsN1SonPKgLR3koQrnpOBQ.LhSFHp2O0Y6pFHc30rjhJD2sLgQhrRfD63MWdjJgUT1lmvctcsSbLMRGr-Vv86Exqo1G4ovMncr9JMLx-IFGK--ABSeM3vYFOe6CeBPgasM.TncKF5TGUvLPBQMWWHXGAt42yUD8wxqfbU5vnoh9v-U'
        payload = b"\xe4\xa6.\xe9d\xe4\x91\xd4\x06\x83r\xc4\xe5\x93,\x89\x1a!\xbb`\xc13\x0e\x98q\xf8\xb9\xe1\x16\xd7V\xfa\x99x\xedm\xb3\xfb\x88\x00\x06\xe3\xbe\x9b\xbc\xbb\x86M?KY\xd8y\xda'{\xe4\xa9\xfc\xdd\xec\x192R*\xec\x81\x8fq\x8e"
        self._run_jwk_decrypt_test(jwk, token, payload)


    def test_decrypt_pbes2_hs512_a256kw_2(self):
        jwk     = b'19232d7012c2c1da6ecb58b8'
        token   = b'eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwicDJjIjo4MTkyLCJwMnMiOiJzR2VFNldQN19vYWdLS2RyS3Ftd2xBIn0.JAwwBEZh4fHjVdhJDELlbvhBXTPcJLS-6ES8svW72npl6aiFtBJqPG2lx53TSQHCaAgvoAGJKWj1C83Dg15ONUUhGdqbBVti.kkRHo1o6K7j8VVPX9FnGXQ.vdiecRmcklGQ8lkalBc1uc9ufZHQROXNXEhPIGDCJbME4-FyUgJle9Q3UFPBw-Jqe-dS5jQw-_HWRWNnU0yA2pf1dqGB-zRcWsUyzK8who8.577yCJl7bbG9KJO2R-fNKAD0iC-jy0kQjJJLw6MQwbg'
        payload = b'A\xd3w\x11\x80H\x8e\xa6\x89\xeb\xbe3\xf2\xbd\xca\xf86\x01\x18\x06\xc9t\xec\x9d\x9b2\xd8\xbdq\x95kg\xb1\r(\xd3:u\xc8R\x18\xeaK\xcf\x08\xcc%\xd0\x16^\x08\xd8\x11\x97\x8f\xc5\xa3\xe4\xfe-\x01\xe0g\xa3<\xc1\x92{_\x8b'
        self._run_jwk_decrypt_test(jwk, token, payload)


    def test_decrypt_ecdh_es_0(self):
        jwk     = b'{"crv":"P-256","d":"K8UtbnatFYecK73ijZtH_lNOl3hmoo_vz7Kuh0tQ9F0","kty":"EC","x":"8UTq-dluyS8EgVwUEgnB3QvC1l_cpzYuz4zGGYx2okA","y":"XiCuPXtrSsN9hzO7g2yt8TU4PEY-bi1Ler0R5yMGseg"}'
        token   = b'eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImVwayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImpEYzdqb3VzQTZlZHBaR1ctVTBWYW1rX01vMzFZNGFjSHI3RmxwVjhRRlkiLCJ5IjoiQ21KdG00cDFLdnI5cU1vNGlhQ0lkNG1BUHh0VURhNlJaZnltMFltaGFZNCJ9fQ..LOLWkCro15t5eERRiPt9pg.crjZv7-3AG0WouzAbVKlxVGlq_9rj2wQch793Uuct7D1DUezBK1Bn5aT1kax2-_Jwqe-mD4IjZQt7gC_3DOGzj4IMhCOi-ydRmZMN0EBCvA.uNy14zIGlW_L38H4LpKkOA'
        payload = b']\x89o\xdd10\xa1\xd2\xc9z\xcb\xa5Ka\xbe\x1a\x94@\xd9A\xca\xeb\x14\x7f\xf6\xfd\xb1\xc1\xf8\xc0\xde9\xd2v\x13f\xcc\xbe\x1a\xf3\x8e\xff;\xc9\xa7e\x13\xfaT\xd2]Q\x96DJ_\xe7\x9eyX\xd0\x17\xa1\xba\x97\xf0\xdd.\x88\xe8'

        self._run_ecdh_decrypt_test(jwk, token, payload)


    def test_decrypt_ecdh_es_1(self):
        jwk     = b'{"crv":"P-384","d":"2E1VTcfGkwjtMoi_H3nWO8zYUveaLEtEXPA49cWkXN4Y_TmPAuys2GXmfmq1xP12","kty":"EC","x":"LRSiTIXR1uYUCHY_z7huyMc5pdztKKSdLvjta-HolmmKhj0PIxkc9Jb2ry98Xm73","y":"eMycX7F57phl9fgKYNnX-otzSdnmZjchtJgn7Obz01caMEUk2AC9c_voMRBUhkto"}'
        token   = b'eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTE5MkNCQy1IUzM4NCIsImVwayI6eyJjcnYiOiJQLTM4NCIsImt0eSI6IkVDIiwieCI6IklVZGMtZUpzYkFQSlhqWDR6QTJydDJxaUJ3ODk0M1FOYWNUd3F5N2NkTjdvOGJCNHVRd0owSFVxWVBGOHFnRC0iLCJ5IjoiOU9VV1RYTDZYQXljRlNHRXBtX0p1MEw3SDY2RzBGam9FRmdDWjhHck9iNHMyUVhQUXNZQURYVUp6dlhIX1RLOSJ9fQ..KQISHfUqt9hqVVogIMvt5w.47HIa3OWoYV1DxZNxrp3LSXNcUad3b86zK2DXZcojoZl-vg3fa6j6jCVIlhnGakBdJUTUGD8-Sx_SD7G9KqoK6Y3XLWgsO31qX3hUgF8K_Y.CJNjTe_pPwqN82hC01amkgKJ-D7DCEdk'
        payload = b'\xc1\xc6\x1a\xcd\xaf\\M)-\x92G\xe1\xebR\x9dR\xfb\xe9\xb2\x98v5\rQ\xde\x9a\xf6A<\xbf3\xb3\xf0\x87H-Uu\xb5s\x0b\x1e0\x06A7\x13\xce\x88\xe1\xd7\xa8j\x07\x8eB!\x98I\xfb\x95Y\xc3\xc7WB\x89\xae\xc3\x81'

        self._run_ecdh_decrypt_test(jwk, token, payload)


    def test_decrypt_ecdh_es_2(self):
        jwk     = b'{"crv":"P-521","d":"Be2LmiMrOakJTz_Sc8ANxTSj3Enf1spk-2Qi_C9k6SOMXs_mgjOT65xknDzF9sl3dGFwNuSt-HIYZGbW--W8iVg","kty":"EC","x":"A1hMsIWAyfI1Tdt2CTaVNwZC7yNQT-O34j80sswEBPQn4Gk6u6hfOEH3zxrQJyLRmGeR4f51WjgMPhbVzl1mlKs","y":"AZiwInsx5gzY12-jipZP_6oAZjfWUn7YzLCjIRPOAj3gIcNU5G1CdrVAoXseM_I2TijNGik7xGyDywji4JsZcSgl"}'
        token   = b'eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkNCQy1IUzUxMiIsImVwayI6eyJjcnYiOiJQLTUyMSIsImt0eSI6IkVDIiwieCI6IlVmWXVDeFREYVVIQ0tGbHVCbjhIVjAtRGQ4aFBWNWd5dDdQVFFlQ0N3QUhLMGZoT3ZfdktHdXRDMVI2WThsR1Y4MmdqVmZOZzdnTGZtRmhvOXdYd05TWSIsInkiOiJBWnd0Ym10cmlZcm5xVkJsRDJnMG9KeXZuUFRZYWwxdzA0MVVDVjU0d01WMHRBUzlDS3RNS3o2Zkstby1tSGxhWmtRWW5iZDRtZGVHNW1vTnBzZENtbEdRIn19..jkHhj8VUwzT1gAcaJ4Hrhw.mjJVhIWYl3pPuhnPLjQk7my-v1JHDgQRw84ieG-u4uKeCvU7FPb0NWLLP7QbyjPrbd8c4wpu--x03VcgXb6VvP1_F4IsRTN591rEQXZSOow.K2HbFIJjmQwaUwFRNKOs8VcIfs12C7erTg7HUFGIZTk'
        payload = b"$;H\xff=\xe8\xdd\xe5e\x9e{S\x92\xaf$\x86\x17\x1dH\x8a0\xe1\x97\x16\xe4\xd9=\x0e'\xf7\x03>\xa9\x81\xec\xb7\xe6\x83\x83\x86\x90\x1f,\x8dX\x07\xea\x1f\x8c\xe3\xb5\x04\xbe\x99\xfa\r\xc8\x07\x1c\xb3\xd7\x164\x9e\xf7\xb14\xe1\xf0A"

        self._run_ecdh_decrypt_test(jwk, token, payload)


    def test_decrypt_ecdh_es_3(self):
        jwk     = b'{"crv":"P-256","d":"JKFgL6gFTsUJlszoXn1RrqZRtD0zimGVvG5tQqOcWWI","kty":"EC","x":"xOGSMDt9f4FYh4og2_fNeQKejBJPJVSbjfN0uhC8YkU","y":"obZVJyiqDgRBqyk4XaSanlArC03WQTYkrTI6uwtD4Tw"}'
        token   = b'eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSIsImVwayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IlhXa0YxeFhQeEtzV1V0UGFBREhGRm84SzBaeEZTYWNlQ1FHWTA4NGhpOEUiLCJ5IjoiU010cEdmdTRxZFJ0dkgzU0kxQ0dHNjdTcEJ5ZUxQeV9HbzlzV0xWY3BCdyJ9fQ..uOGRJp-lRmt2AXXI.MnrGgiZ09oFpSN8ZFTJbA9Pwlb2-eJ6DQGZaw6_YY_fAJYMoOe8_pUmRUxM1FTYyoL90XxX0YLrDxDJY4MALiqX3QrSpPw.RMn7YUnlIQDSEUAqaKrjpA'
        payload = b'm\xb4\xe2@\xcb5\x18\x13\xa1\xf5\xd0\xd3\xb3\xc6\xb4\x89XB\x17\xa7\x8aq\xdb?>\xb4\xf7SN\x04<yo\x1c\x83\x00\xf5\xa7\xcf}\x91\xc6L\xdbm;y\x18-\xac\xc6\x82I\xbak\xd0u\x1d\xcb\xe5\xbe\x8e&\x1a\xfc\x0c\xbd\x11\xc3\x14'

        self._run_ecdh_decrypt_test(jwk, token, payload)


    def test_decrypt_ecdh_es_4(self):
        jwk     = b'{"crv":"P-384","d":"3Irb1TlYsxYxtmcI6ZrdrY8IxFlQXvPX5mmxtKfmrLHUvNRbtxg2clxyqAqWa6O8","kty":"EC","x":"QL00ep91W9_dDEhHLrhChqm7PO4B3c-HD5Czh2stmHAFIfCbxN_O3sgUMRhXAmCK","y":"bJAIiLCfUqOLJ7fARw9Ptl1lmDt4lttW2ikrXr6u19k2l9bwCMxPcQRDIKdXRZi6"}'
        token   = b'eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTE5MkdDTSIsImVwayI6eyJjcnYiOiJQLTM4NCIsImt0eSI6IkVDIiwieCI6Ilp0OFEzZXdEMVpUc0I0bXhGREpHclpIVVpIZ2ZjUVZvSWFzVUFVQk80bXcyalRzYnNlQWJXRGUyalZmdGRYU1UiLCJ5IjoiaWxXaEhqTTRvX0ExeWJ0NDhKYmpIZFNkSjJrUzJibTByT0NaUFRyanFvOXlLZFdDWHBsNGF3bmNYZno3ekc5MCJ9fQ..Y4-BJvetQf9c4Ymz.1IDtL2CP27a2ARx0maCNFn65Bvz8Ju-8E9CUWP4X6PrQ1l-mvjHvaXopcECJqCLDdFtaERMwqAjErJTFotnIzMSQorjW3g.L13WhCokbIelQQfSC3CbWw'
        payload = b'Y6\xf4+x\xd8\xaa\xa1{]GGU\x06\x89\xed\xd6u\xd9\x1c\xeb\xfb7\xf5\xf14\x0b\xf2JM&\x05C\x83\x9cs\xd2\xf3x\xf6TG\t\xbc\xd608\x05\xcf\xe0\x15\x81^\x0c2\xdd\xdc\xe1M\xc1\x0c\\\xaf\x99\xa3L+4[H'

        self._run_ecdh_decrypt_test(jwk, token, payload)


    def test_decrypt_ecdh_es_5(self):
        jwk     = b'{"crv":"P-521","d":"AdXVZTQT6xM3-D5_2XtE0ps58XYq_QgHEhqdR3zGdiZPJmgIxnI9rEguxhWoKvr5FRQD_oHrS6ouUkXE9uKyoBoI","kty":"EC","x":"AS9awG05UQ8UEYbjTizg2YcbT8SjvOKssEsq5ITaJAVbZ0c9-wqUo8G8T8FpzxcRXjyDiZGKnEe0IJg6EyPGjl1V","y":"PE8551Ygp3QIrA1DqFA0G6b1-3tLQ1JMDL2RpEr2g84UCWNIkReq_Xpz0n8bVzcQa_kiCZvN0JhCwsS0gTwq03M"}'
        token   = b'eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImVwayI6eyJjcnYiOiJQLTUyMSIsImt0eSI6IkVDIiwieCI6IkFZZHdSRmtLcHNXeXlwZmVHMEVfU3BLMmNnc3k0YTdrX0tGbmxUaXI3b19sQ25VM2ZDMUpaQ0x6VjNnRHlhZVFGS0sxbENkcWZyQ1BkQlVXVnhndC1sM0oiLCJ5IjoiM1VUU3ZlSV9adk16LVRRUjRpWlZ5TUxBZVlmb01OQzE2ZE5MT0s4bG5sdHM3Sm1xVzZwZm5kWDNNdFBqenlWaDZudDVLM0dMcDlBdUIwaExIOHZPejFNIn19..RyGnhEPToyrccchU.k2v18qZAS6VA3-UG9nxKbdooFivr4tNwQ9DeueFgT3gXPuA5AHKwHH_OjeLRju6NWEyp4Dz3pD1As6nMvLHoDAnWMZ3QSA.UhkaLDW2x0jEhlEfjXq94w'
        payload = b"RBHN.{\x19`\x8e\xda8\xe9\n\xde\x82\x8a\xc9\xf0<\xd3U`\x99\xf2s=\x94\xd2c\xb4fm\xbaz+B\xfc\xa8\xac'g\x14\x88\xa4?\xc0@`\x06v\x0f\x94\x0fs9\x00Z%\x07\xc5x\xeb\t]4**\xf3\xf4,"

        self._run_ecdh_decrypt_test(jwk, token, payload)


    def test_decrypt_ecdh_es_akw_0(self):
        jwk     = b'{"crv":"P-256","d":"4zy1D9r4CcfEl4RkkKx5r9lhcfWcZFa17fftMNfCiQI","kty":"EC","x":"9NZ9r1_L41Pq2pFO1RDCnUxctaBSPKKEDM8Svj0Jlq4","y":"h2Dx5ZXvLO7dfxWHhGRTKXupYEm-zR84g_hgjaGlo30"}'
        token   = b'eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJoa3F4bzRDR1lZbjhoeEZSekhrdld3a3lrQ0JUMlJQa1N5T004RHpfRlRvIiwieSI6Ijd1bVJfTEhLcWZZNHZnb1Njd3hWeEplRkQ0N3FMbmh3M2w0bVg5QW54MkUifX0.sqjGS0p3-_mwZfj_C2mrXKg8Eeja4li3G7JwNuCWTSygbP3qh5-oTw.YwK3OyopCuhBe-c52Ykbvw.S8dssdprF9ZlNlh-k6DLr8dBvaZ1IDOGM6djsEtb49MofyfF3APsptjCvBw3CdBIgZlSuLd7zMm93sXoXRU8I5Y9RPdidm0oUN2WPoO-Rbc.NDs6zFRkx1Yzgz_26po2Yg'
        payload = b'l\xb5\xd2\x1d\x943j\xfd/\x9b\xeb\xddBx\x0cyc\xcc\x8d\xe5\x15<\x07Z\xfa\x8bwk\xc8\x1a\xb2\xc6\xb1\x10J_\x1b\xd1\x17\xd4\x1f5?5\x15T\x0b\x84y\x9c\xdd#{\xdf\xe8C\x84Be1\xb5o\xeb\xce\r\x7f\xdb\xf6\x16s'

        self._run_ecdh_decrypt_test(jwk, token, payload)


    def test_decrypt_ecdh_es_akw_1(self):
        jwk     = b'{"crv":"P-256","d":"oqtedFYT0R3MAbB0b4NvPWODh1fDWKASptkpxfJAp9U","kty":"EC","x":"AoLM8aD4WfIFTgUqGk6EZcIuvGCY1-563RSjiGxxJG8","y":"kW_9LC0m-BzXWg9QefC1nctT3sVkNkKlYnd8OZ_KnQ"}'
        token   = b'eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJ4QWYwb0p4MXY3U0VUbnFjX1ZLM0RPV3RiZ3VkUGpRd092TlhRTXJBeGNnIiwieSI6IjkzbTl3QVJfN19xQnZMRkN1cEdiN194S01OSmxxcER4bW1KMWZuWlRHYzAifX0.Hdaje0ecM2L9p5UzbmQQLilV2gbUNgCbG6yEOXPXAXJAKlnA-lDxuQ.eUP9ILrGUsOgc6F1iYZ9Tg.EAc1SPgiyKHhEYqP7GH4z4yKRpHer31Ov1KbTxVT_ZYiwm7UusYNmzPtitHilglGZe8dbsqW5EhahQJYdSMp3rWM_YzacGyDmvhKnD-YvRs.nB84saO0VhnRg3a9Irw0lw'
        payload = b',\xcf\xd5S\xba\xe6\xf5\x1cc=\xc0\xdc\x90\xc4\xd6\x01R\x7f\xda\xc6{oP\xe7\t\x8a\x18\xed\xfe-\xfdC\x8dy\xa0\xfcEEYBo~\x18\xa7Z\x0e.\xbfp\xd5\xc0sw\x8bG\xc9Z\xf1\xc7\xbb\xf5@w\x19\xb1/\x987K\x9d'

        self._run_ecdh_decrypt_test(jwk, token, payload)


    def test_decrypt_ecdh_es_akw_2(self):
        jwk     = b'{"crv":"P-384","d":"zEWmTcAin5mjv837FgJXvkv8gQaeTxoxbBRYtqwFKyrpBWDtBAeILWgNfdrF4aaB","kty":"EC","x":"su_nb0zJ7IcT0ISm10ARj1M_dhA3QwQO5jO41B9qlH7UYWStYg-NTxJncPNSzBOj","y":"lPDKdaUNdDO-2m2dBEdyVCy1LsfKb8V7Dk6IURyUQUSfZshYqPBQ4nlzw93Up9Dw"}'
        token   = b'eyJhbGciOiJFQ0RILUVTK0ExOTJLVyIsImVuYyI6IkExOTJDQkMtSFMzODQiLCJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJVWm9BVF94Z21HMFFna2k3dXk2clhOcUlMampZSlAwd1NnbVYxSE5SQUFaU2x5U01LY1dsUWZIVzJ1Qi1KT1hLIiwieSI6InBlMzlPTWZoY1pwamo4RDFRS3NESENfRFBCTHBfMDFQZnBycjh4LVBsZXVtS0pmMXl0ZnNOcXZuVjVPQTJlZ3AifX0.AzrxGb6SqiBfJv1ndvpYa0tDSreXdJwyzZhiLQZAm40P9erJF9NBL5Exd8gQwwRFKqZLEiVOh5Y.drc4A_xrSwol6i2N4y2olQ.A7ldRu8s0ByToOaTH4-A1uj5qZrfs409SCL5ypv-jHic3p9-YdtISVa5naXhV7ssLtlKDBFnffLwUDa9NJfQgb-Do_XVxgEflH-5qL5mR0Q.rBnPcLoluyQP30g3UYO85LXAr6-fOmyD'
        payload = b'\xd3\xceZ\x8e\xb7\x17\x14\x0f\xe9\x8eU\x10\x02\xa3\xad-\xfdPn\x05\x96\xdb\x19\x0cn\xb4Ad\xc6\xf8\xc5@@\xc9f\x00\xc5\xf9\x1f-_\x96\x08\xe5@{\xdb\x8f\xec\xc2\xb7\x9a\x86Cr\x13Xo\xbb\x16\xce\x00Q=\xadt\xfbIF\x1b'

        self._run_ecdh_decrypt_test(jwk, token, payload)


    def test_decrypt_ecdh_es_akw_3(self):
        jwk     = b'{"crv":"P-521","d":"xH4jO2zVkGEP6pb_xrollDsrF1ILYop8IU5irVO_rmjUsA4cZzBXoGyo_vCGC0pm65iEmV7b6ccNq-8jXEr7arw","kty":"EC","x":"AZI1zOnbZW2_SA9wEBU5rbPOTSOxqobRzS6SXPvkP9fqE7Jclpl0aM1jApT9TgWsqOYROBabbNkSkCScWBnj4JAc","y":"AcuDREp5c8Xq1n1FLup5Aj2DNcVv3LPLkScoMj4Ni9bWbfqsp-aCd5JTAZtA_dwbM7U-aqTuZJOeD-FM8TSnC2kz"}'
        token   = b'eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJSOWRFeFBzU2xuUHB2eWFSVkNlQ1VZRXI5c2pOY0c2U1lWR0tDODRnbmp0RmdVLXQzMS1RanhWeUJYNGJZcTEtdnN3NnRGQkZWV3RjdDNiVXVwc3M1Wk0iLCJ5IjoiQVI1ZzZIbHZPczR0clhzd1RBRjhteUt1bTVBMHZrTGhFQmdzNml3UEJtZVB3cU9Ca3RZWjNlSTNOUzNNYUN1VUxxZG1oalZOQ000cEFlTkxnZWt1TDB6diJ9fQ.BF9yyAB4cUTcjOFzfn0Fjeyc-VNNlyeYRLqQdtRwOlSrMgjCbhJzSdfsdjIVjcY36jTo1OorUrtf8BKaBoxsZZJFAOXAXCNv.LgCVNVEyUuCgkCgyHyXRog.T_VLtGdAvNMG05EB8tnAR4nLybmLdizUVb5zASxqP5OovDWEUAhWESenaeNQ092mTURt7_SVyJn8jD6YpblGyCseQuZF_1bRAcytA9il3RQ.yRFZgbOvLmTD-fU33BGGnoSg8NJCmh8fyA-bkIgl0J8'
        payload = b'\x82\xbc\x03\xa99\x97n\x95#y#@\x1c\xf6YJ1R\xe7\xe8u\x8d\xbe\x8f\xe9~\xa2\xae\x1f\x8e\x08\xd2F\x8b\xc7S\x8dN\x07\x83K!S\x1ax\xbb4\x1a\x04\x02.\xbe\x96%\x94>\xa3$\xbc\x8d"\x9e\xc1\x7f\xa8\xc7\xd3\xa6\xb9\xff'

        self._run_ecdh_decrypt_test(jwk, token, payload)
