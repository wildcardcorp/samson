from samson.protocols.jwt.jwa import JWAContentEncryptionAlg, JWAKeyEncryptionAlg, JWA_ALG_MAP
from samson.protocols.jwt.jwe import JWE
from samson.encoding.jwk.jwk_oct_key import JWKOctKey
from samson.utilities.bytes import Bytes
import unittest


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



    def test_gauntlet(self):
        for alg, key_gen in [(JWAKeyEncryptionAlg.A128KW, lambda: Bytes.random(16)), (JWAKeyEncryptionAlg.A192KW, lambda: Bytes.random(24)), (JWAKeyEncryptionAlg.A256KW, lambda: Bytes.random(32))]:
            for enc in [JWAContentEncryptionAlg.A128CBC_HS256, JWAContentEncryptionAlg.A192CBC_HS384, JWAContentEncryptionAlg.A256CBC_HS512, JWAContentEncryptionAlg.A128GCM, JWAContentEncryptionAlg.A192GCM, JWAContentEncryptionAlg.A256GCM]:
                for i in range(5):
                    key       = key_gen()
                    plaintext = Bytes.random(128)
                    jwe       = JWE.create(alg=alg, enc=enc, body=plaintext, key=key)

                    try:
                        ciphertext = jwe.decrypt(key)
                    except Exception as e:
                        print('Iteration', i)
                        print('Key', key)
                        print('Plaintext', plaintext)
                        print('JWE', jwe)
                        raise e

                    self.assertEqual(ciphertext, plaintext)


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

    def _run_oct_decrypt_test(self, jwk, token, expected_payload):
        key   = JWKOctKey.decode(jwk)
        jwe   = JWE.parse(token)
        self.assertEqual(jwe.decrypt(key), expected_payload)


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
