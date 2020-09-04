from samson.utilities.bytes import Bytes
from samson.encoding.general import PKIEncoding
from samson.public_key.eddsa import EdDSA
from samson.math.algebra.curves.named import EdwardsCurve25519, EdwardsCurve448
from samson.hashes.sha2 import SHA512
from samson.hashes.sha3 import SHAKE256
import unittest

TEST_SSH_PRIV = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBct6kHgZO1njzDIC75re+m3clCzKTQlBNM3t/MMwoSwQAAAJibx2Cum8dg
rgAAAAtzc2gtZWQyNTUxOQAAACBct6kHgZO1njzDIC75re+m3clCzKTQlBNM3t/MMwoSwQ
AAAEAzRlV4oo+r1+CWXJRbA7mg19t37FRDj2CuPIqiTw0kSVy3qQeBk7WePMMgLvmt76bd
yULMpNCUE0ze38wzChLBAAAAEWRvbmFsZEBEb25hbGQtTUJQAQIDBA==
-----END OPENSSH PRIVATE KEY-----"""


TEST_SSH_PUB = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFy3qQeBk7WePMMgLvmt76bdyULMpNCUE0ze38wzChLB nohost@localhost"

TEST_SSH2_PUB = b"""---- BEGIN SSH2 PUBLIC KEY ----
Comment: "256-bit ED25519, converted by nohost@localhost from OpenSSH"
AAAAC3NzaC1lZDI1NTE5AAAAIFy3qQeBk7WePMMgLvmt76bdyULMpNCUE0ze38wzChLB
---- END SSH2 PUBLIC KEY ----"""


TEST_SSH2_PUB_NO_CMT = b"""---- BEGIN SSH2 PUBLIC KEY ----
AAAAC3NzaC1lZDI1NTE5AAAAIFy3qQeBk7WePMMgLvmt76bdyULMpNCUE0ze38wzChLB
---- END SSH2 PUBLIC KEY ----"""


# ssh-keygen -t ed25519 -f ssh0
# ssh-keygen -t ed25519 -f ssh1
# ssh-keygen -t ed25519 -f ssh2 -N '934495604a1e0cfe'
# ssh-keygen -t ed25519 -f ssh3 -N 'd133d14b43d1a42f'

TEST_OPENSSH0 = (b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCZztxi9GNkL4YeuAn3ud0D4yY7dnp6D4zr6PaLvfUJiAAAAJhyLKRhciyk
YQAAAAtzc2gtZWQyNTUxOQAAACCZztxi9GNkL4YeuAn3ud0D4yY7dnp6D4zr6PaLvfUJiA
AAAEAqNbIVBf0bVPEo3XM07befF8WntPsUsoBOU3DgeSPCg5nO3GL0Y2Qvhh64Cfe53QPj
Jjt2enoPjOvo9ou99QmIAAAAEWRvbmFsZEBEb25hbGQtTUJQAQIDBA==
-----END OPENSSH PRIVATE KEY-----""", None)

TEST_OPENSSH1 = (b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBF0siswWzn50v+fTwkEpTf0IUMoAWc4PZt6XrCsvU0LAAAAJiGkZahhpGW
oQAAAAtzc2gtZWQyNTUxOQAAACBF0siswWzn50v+fTwkEpTf0IUMoAWc4PZt6XrCsvU0LA
AAAECkW+m9PNS4SmPFNB9maqJtak2CjtkkZlAg3gw7qWGNf0XSyKzBbOfnS/59PCQSlN/Q
hQygBZzg9m3pesKy9TQsAAAAEWRvbmFsZEBEb25hbGQtTUJQAQIDBA==
-----END OPENSSH PRIVATE KEY-----""", None)

TEST_OPENSSH2 = (b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBE8k7xL2
ywJPEcJegAFnIxAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIL6SwZdHYjMvWvWH
vu+YYT4f0F2atgxbSlniCUbcG59xAAAAoIj1P/qxC9ei4XuBeTQ0dvbQwu13wwgpc47Mq9
jF/4IDjhqzOg+McKl4c9OdclXVqohu7Aeeyha4YB0UYQ81f+RV+95rMUI282txXkehPGtM
Fw6lOTkvhHk5GaEEXTgPdg8YWQOUzgRDcb38NuONXTj/DkKvGsQsdXDxHoMbZF/o/NOkos
ssDCHzotPaK5nNnuWbpG6AnGNsuusYRyxEbpQ=
-----END OPENSSH PRIVATE KEY-----""", b'934495604a1e0cfe')

TEST_OPENSSH3 = (b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBjV526pf
NgcquPjbhjTY3sAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIDPvMKkF2zLxAUXQ
rlyyO5Hxu7y/7W+5jcicSOzzBFRsAAAAoGOaufFSN7t2t7imEgM1F8MGnUfxHVCJ9Nz/2y
iTNedFNKH0WvbLn89u06TphI3bka1gta0ref/N13Plo8uPkwvjrm9oAtTnjsrZ6ApNwt9B
A+XJo6me3WIQ7MqA2aZ8t0IL8fmIB80ojE0VbR7XlcCn298SgOV95dJT7KO1KSaDwTYFko
euMpFa0COjJ4Pk0WBhJMdN3+U8UNKqU6meEg8=
-----END OPENSSH PRIVATE KEY-----""", b'd133d14b43d1a42f')


# https://tools.ietf.org/html/rfc8410#section-10.3
TEST_PKCS8 = b"""-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
-----END PRIVATE KEY-----"""


TEST_X509 = b"""-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----"""


TEST_JWK = b"""{
   "kty" : "OKP",
   "crv" : "Ed25519",
   "x"   : "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
   "d"   : "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
}""".replace(b"\n", b"").replace(b" ", b"")


# https://tools.ietf.org/html/rfc8032#section-7.1
class EdDSATestCase(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None


    def test_import_ssh(self):
        priv  = EdDSA.import_key(TEST_SSH_PRIV).key
        pubv1 = EdDSA.import_key(TEST_SSH_PUB).key
        pubv2 = EdDSA.import_key(TEST_SSH2_PUB).key

        self.assertEqual(priv.A, pubv1.A)
        self.assertEqual(priv.A, pubv2.A)

        self.assertEqual(pubv1.export_public_key(encoding=PKIEncoding.OpenSSH).encode().replace(b'\n', b''), TEST_SSH_PUB.replace(b'\n', b''))
        self.assertEqual(pubv2.export_public_key(encoding=PKIEncoding.SSH2).encode().replace(b'\n', b''), TEST_SSH2_PUB_NO_CMT.replace(b'\n', b''))



    def test_import_openssh(self):
        for key, passphrase in [TEST_OPENSSH0, TEST_OPENSSH1, TEST_OPENSSH2, TEST_OPENSSH3]:
            if passphrase:
                with self.assertRaises(ValueError):
                    EdDSA.import_key(key).key

            eddsa = EdDSA.import_key(key, passphrase=passphrase).key

            # EdDSA's little-endian causes a pretty big headache
            other_eddsa = EdDSA(h=eddsa.h[:32][::-1], clamp=False)

            self.assertEqual(eddsa.a, other_eddsa.a)



    def test_openssh_gauntlet(self):
        num_runs = 1
        num_enc = num_runs // 3
        for i in range(num_runs):
            eddsa = EdDSA()
            passphrase = None
            if i < num_enc:
                passphrase = Bytes.random(Bytes.random(1).int())

            priv        = eddsa.export_private_key(encoding=PKIEncoding.OpenSSH).encode(encryption=b'aes256-ctr', passphrase=passphrase)
            pub_openssh = eddsa.export_public_key(encoding=PKIEncoding.OpenSSH).encode()
            pub_ssh2    = eddsa.export_public_key(encoding=PKIEncoding.SSH2).encode()

            new_priv        = EdDSA.import_key(priv, passphrase=passphrase).key
            new_pub_openssh = EdDSA.import_key(pub_openssh).key
            new_pub_ssh2    = EdDSA.import_key(pub_ssh2).key

            self.assertEqual((new_priv.h, new_priv.a, new_priv.A), (eddsa.h, eddsa.a, eddsa.A))
            self.assertEqual((new_pub_openssh.a, new_pub_openssh.A), (eddsa.a, eddsa.A))
            self.assertEqual((new_pub_ssh2.a, new_pub_ssh2.A), (eddsa.a, eddsa.A))



    def test_import_pkcs8(self):
        priv = EdDSA.import_key(TEST_PKCS8).key

        priv_out = priv.export_private_key(encoding=PKIEncoding.PKCS8).encode()

        self.assertEqual((priv.d, priv.curve), (Bytes(0xD4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842), EdwardsCurve25519))
        self.assertEqual(priv_out.replace(b'\n', b''), TEST_PKCS8.replace(b'\n', b''))


    def test_import_x509(self):
        eddsa = EdDSA.import_key(TEST_X509).key

        self.assertEqual((eddsa.A.x, eddsa.A.y), (14952151952356719083710889065620775312428310390022181962301901207657981878023, 44054905936511465773410409843262024357620586324426155423091388570442095968025))
        self.assertEqual(eddsa.export_public_key(encoding=PKIEncoding.X509).encode().replace(b'\n', b''), TEST_X509.replace(b'\n', b''))


    def test_import_jwk(self):
        eddsa = EdDSA.import_key(TEST_JWK).key

        self.assertEqual((eddsa.A.x, eddsa.A.y), (38815646466658113194383306759739515082307681141926459231621296960732224964046, 11903303657706407974989296177215005343713679411332034699907763981919547054807))
        self.assertEqual(eddsa.d, b'\x9da\xb1\x9d\xef\xfdZ`\xba\x84J\xf4\x92\xec,\xc4DI\xc5i{2i\x19p;\xac\x03\x1c\xae\x7f`')
        self.assertEqual(eddsa.export_private_key(encoding=PKIEncoding.JWK).encode().replace(b'\n', b'').replace(b' ', b''), TEST_JWK)




    def _run_test(self, message, d, curve, hash_alg, expected_public_key=None, expected_sig=None):
        eddsa = EdDSA(d=d, curve=curve, hash_obj=hash_alg)
        sig = eddsa.sign(message)

        if expected_public_key:
            self.assertEqual(eddsa.encode_point(eddsa.A).int(), expected_public_key)

        if expected_sig:
            self.assertEqual(sig, expected_sig)

        self.assertTrue(eddsa.verify(message, sig))


    def _run_25519_test(self, message, d, expected_public_key=None, expected_sig=None):
        curve    = EdwardsCurve25519
        hash_alg = SHA512()
        self._run_test(message, d, curve, hash_alg, expected_public_key, expected_sig)


    def _run_448_test(self, message, d, expected_public_key=None, expected_sig=None):
        curve    = EdwardsCurve448
        hash_alg = SHAKE256(912)
        self._run_test(message, d, curve, hash_alg, expected_public_key, expected_sig)



    def test_gauntlet_25519(self):
        for _ in range(10):
            message             = Bytes.random(256)
            d                   = Bytes.random(32)
            self._run_25519_test(message, d)


    def test_gauntlet_448(self):
        for _ in range(10):
            message             = Bytes.random(256)
            d                   = Bytes.random(57)
            self._run_25519_test(message, d)


    def test_vec0(self):
        message             = Bytes(b'')
        d                   = 0x9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
        expected_public_key = Bytes(0xd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a)[::-1].int()
        expected_sig        = Bytes(0xe5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b)

        self._run_25519_test(message, d, expected_public_key, expected_sig)


    def test_vec1(self):
        message             = Bytes(0x72)
        d                   = 0x4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb
        expected_public_key = Bytes(0x3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c)[::-1].int()
        expected_sig        = Bytes(0x92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00)

        self._run_25519_test(message, d, expected_public_key, expected_sig)


    def test_vec2(self):
        message             = Bytes(0x08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0)
        d                   = 0xf5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5
        expected_public_key = Bytes(0x278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e)[::-1].int()
        expected_sig        = Bytes(0x0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03)

        self._run_25519_test(message, d, expected_public_key, expected_sig)


    def test_vec3(self):
        message             = Bytes(0xddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f)
        d                   = 0x833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42
        expected_public_key = Bytes(0xec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf)[::-1].int()
        expected_sig        = Bytes(0xdc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704)

        self._run_25519_test(message, d, expected_public_key, expected_sig)


    def test_vec4(self):
        message             = Bytes(b'')
        d                   = 0x6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b
        expected_public_key = Bytes(0x5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180)[::-1].int()
        expected_sig        = Bytes(0x533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600)

        self._run_448_test(message, d, expected_public_key, expected_sig)

    def test_vec5(self):
        message             = Bytes(0x03)
        d                   = 0xc4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e
        expected_public_key = Bytes(0x43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480)[::-1].int()
        expected_sig        = Bytes(0x26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00)

        self._run_448_test(message, d, expected_public_key, expected_sig)


    def test_vec6(self):
        message             = Bytes(0x0c3e544074ec63b0265e0c)
        d                   = 0xcd23d24f714274e744343237b93290f511f6425f98e64459ff203e8985083ffdf60500553abc0e05cd02184bdb89c4ccd67e187951267eb328
        expected_public_key = Bytes(0xdcea9e78f35a1bf3499a831b10b86c90aac01cd84b67a0109b55a36e9328b1e365fce161d71ce7131a543ea4cb5f7e9f1d8b00696447001400)[::-1].int()
        expected_sig        = Bytes(0x1f0a8888ce25e8d458a21130879b840a9089d999aaba039eaf3e3afa090a09d389dba82c4ff2ae8ac5cdfb7c55e94d5d961a29fe0109941e00b8dbdeea6d3b051068df7254c0cdc129cbe62db2dc957dbb47b51fd3f213fb8698f064774250a5028961c9bf8ffd973fe5d5c206492b140e00).zfill(114)

        self._run_448_test(message, d, expected_public_key, expected_sig)


    def test_vec7(self):
        message             = Bytes(0x64a65f3cdedcdd66811e2915)
        d                   = 0x258cdd4ada32ed9c9ff54e63756ae582fb8fab2ac721f2c8e676a72768513d939f63dddb55609133f29adf86ec9929dccb52c1c5fd2ff7e21b
        expected_public_key = Bytes(0x3ba16da0c6f2cc1f30187740756f5e798d6bc5fc015d7c63cc9510ee3fd44adc24d8e968b6e46e6f94d19b945361726bd75e149ef09817f580)[::-1].int()
        expected_sig        = Bytes(0x7eeeab7c4e50fb799b418ee5e3197ff6bf15d43a14c34389b59dd1a7b1b85b4ae90438aca634bea45e3a2695f1270f07fdcdf7c62b8efeaf00b45c2c96ba457eb1a8bf075a3db28e5c24f6b923ed4ad747c3c9e03c7079efb87cb110d3a99861e72003cbae6d6b8b827e4e6c143064ff3c00).zfill(114)

        self._run_448_test(message, d, expected_public_key, expected_sig)


    def test_vec8(self):
        message             = Bytes(0x64a65f3cdedcdd66811e2915e7)
        d                   = 0x7ef4e84544236752fbb56b8f31a23a10e42814f5f55ca037cdcc11c64c9a3b2949c1bb60700314611732a6c2fea98eebc0266a11a93970100e
        expected_public_key = Bytes(0xb3da079b0aa493a5772029f0467baebee5a8112d9d3a22532361da294f7bb3815c5dc59e176b4d9f381ca0938e13c6c07b174be65dfa578e80)[::-1].int()
        expected_sig        = Bytes(0x6a12066f55331b6c22acd5d5bfc5d71228fbda80ae8dec26bdd306743c5027cb4890810c162c027468675ecf645a83176c0d7323a2ccde2d80efe5a1268e8aca1d6fbc194d3f77c44986eb4ab4177919ad8bec33eb47bbb5fc6e28196fd1caf56b4e7e0ba5519234d047155ac727a1053100).zfill(114)

        self._run_448_test(message, d, expected_public_key, expected_sig)


    def test_vec9(self):
        message             = Bytes(0xbd0f6a3747cd561bdddf4640a332461a4a30a12a434cd0bf40d766d9c6d458e5512204a30c17d1f50b5079631f64eb3112182da3005835461113718d1a5ef944)
        d                   = 0xd65df341ad13e008567688baedda8e9dcdc17dc024974ea5b4227b6530e339bff21f99e68ca6968f3cca6dfe0fb9f4fab4fa135d5542ea3f01
        expected_public_key = Bytes(0xdf9705f58edbab802c7f8363cfe5560ab1c6132c20a9f1dd163483a26f8ac53a39d6808bf4a1dfbd261b099bb03b3fb50906cb28bd8a081f00)[::-1].int()
        expected_sig        = Bytes(0x554bc2480860b49eab8532d2a533b7d578ef473eeb58c98bb2d0e1ce488a98b18dfde9b9b90775e67f47d4a1c3482058efc9f40d2ca033a0801b63d45b3b722ef552bad3b4ccb667da350192b61c508cf7b6b5adadc2c8d9a446ef003fb05cba5f30e88e36ec2703b349ca229c2670833900).zfill(114)

        self._run_448_test(message, d, expected_public_key, expected_sig)


    def test_vec10(self):
        message             = Bytes(0x15777532b0bdd0d1389f636c5f6b9ba734c90af572877e2d272dd078aa1e567cfa80e12928bb542330e8409f3174504107ecd5efac61ae7504dabe2a602ede89e5cca6257a7c77e27a702b3ae39fc769fc54f2395ae6a1178cab4738e543072fc1c177fe71e92e25bf03e4ecb72f47b64d0465aaea4c7fad372536c8ba516a6039c3c2a39f0e4d832be432dfa9a706a6e5c7e19f397964ca4258002f7c0541b590316dbc5622b6b2a6fe7a4abffd96105eca76ea7b98816af0748c10df048ce012d901015a51f189f3888145c03650aa23ce894c3bd889e030d565071c59f409a9981b51878fd6fc110624dcbcde0bf7a69ccce38fabdf86f3bef6044819de11)
        d                   = 0x2ec5fe3c17045abdb136a5e6a913e32ab75ae68b53d2fc149b77e504132d37569b7e766ba74a19bd6162343a21c8590aa9cebca9014c636df5
        expected_public_key = Bytes(0x79756f014dcfe2079f5dd9e718be4171e2ef2486a08f25186f6bff43a9936b9bfe12402b08ae65798a3d81e22e9ec80e7690862ef3d4ed3a00)[::-1].int()
        expected_sig        = Bytes(0xc650ddbb0601c19ca11439e1640dd931f43c518ea5bea70d3dcde5f4191fe53f00cf966546b72bcc7d58be2b9badef28743954e3a44a23f880e8d4f1cfce2d7a61452d26da05896f0a50da66a239a8a188b6d825b3305ad77b73fbac0836ecc60987fd08527c1a8e80d5823e65cafe2a3d00).zfill(114)

        self._run_448_test(message, d, expected_public_key, expected_sig)


    def test_vec11(self):
        message             = Bytes(0x6ddf802e1aae4986935f7f981ba3f0351d6273c0a0c22c9c0e8339168e675412a3debfaf435ed651558007db4384b650fcc07e3b586a27a4f7a00ac8a6fec2cd86ae4bf1570c41e6a40c931db27b2faa15a8cedd52cff7362c4e6e23daec0fbc3a79b6806e316efcc7b68119bf46bc76a26067a53f296dafdbdc11c77f7777e972660cf4b6a9b369a6665f02e0cc9b6edfad136b4fabe723d2813db3136cfde9b6d044322fee2947952e031b73ab5c603349b307bdc27bc6cb8b8bbd7bd323219b8033a581b59eadebb09b3c4f3d2277d4f0343624acc817804728b25ab797172b4c5c21a22f9c7839d64300232eb66e53f31c723fa37fe387c7d3e50bdf9813a30e5bb12cf4cd930c40cfb4e1fc622592a49588794494d56d24ea4b40c89fc0596cc9ebb961c8cb10adde976a5d602b1c3f85b9b9a001ed3c6a4d3b1437f52096cd1956d042a597d561a596ecd3d1735a8d570ea0ec27225a2c4aaff26306d1526c1af3ca6d9cf5a2c98f47e1c46db9a33234cfd4d81f2c98538a09ebe76998d0d8fd25997c7d255c6d66ece6fa56f11144950f027795e653008f4bd7ca2dee85d8e90f3dc315130ce2a00375a318c7c3d97be2c8ce5b6db41a6254ff264fa6155baee3b0773c0f497c573f19bb4f4240281f0b1f4f7be857a4e59d416c06b4c50fa09e1810ddc6b1467baeac5a3668d11b6ecaa901440016f389f80acc4db977025e7f5924388c7e340a732e554440e76570f8dd71b7d640b3450d1fd5f0410a18f9a3494f707c717b79b4bf75c98400b096b21653b5d217cf3565c9597456f70703497a078763829bc01bb1cbc8fa04eadc9a6e3f6699587a9e75c94e5bab0036e0b2e711392cff0047d0d6b05bd2a588bc109718954259f1d86678a579a3120f19cfb2963f177aeb70f2d4844826262e51b80271272068ef5b3856fa8535aa2a88b2d41f2a0e2fda7624c2850272ac4a2f561f8f2f7a318bfd5caf9696149e4ac824ad3460538fdc25421beec2cc6818162d06bbed0c40a387192349db67a118bada6cd5ab0140ee273204f628aad1c135f770279a651e24d8c14d75a6059d76b96a6fd857def5e0b354b27ab937a5815d16b5fae407ff18222c6d1ed263be68c95f32d908bd895cd76207ae726487567f9a67dad79abec316f683b17f2d02bf07e0ac8b5bc6162cf94697b3c27cd1fea49b27f23ba2901871962506520c392da8b6ad0d99f7013fbc06c2c17a569500c8a7696481c1cd33e9b14e40b82e79a5f5db82571ba97bae3ad3e0479515bb0e2b0f3bfcd1fd33034efc6245eddd7ee2086ddae2600d8ca73e214e8c2b0bdb2b047c6a464a562ed77b73d2d841c4b34973551257713b753632efba348169abc90a68f42611a40126d7cb21b58695568186f7e569d2ff0f9e745d0487dd2eb997cafc5abf9dd102e62ff66cba87)
        d                   = 0x872d093780f5d3730df7c212664b37b8a0f24f56810daa8382cd4fa3f77634ec44dc54f1c2ed9bea86fafb7632d8be199ea165f5ad55dd9ce8
        expected_public_key = Bytes(0xa81b2e8a70a5ac94ffdbcc9badfc3feb0801f258578bb114ad44ece1ec0e799da08effb81c5d685c0c56f64eecaef8cdf11cc38737838cf400)[::-1].int()
        expected_sig        = Bytes(0xe301345a41a39a4d72fff8df69c98075a0cc082b802fc9b2b6bc503f926b65bddf7f4c8f1cb49f6396afc8a70abe6d8aef0db478d4c6b2970076c6a0484fe76d76b3a97625d79f1ce240e7c576750d295528286f719b413de9ada3e8eb78ed573603ce30d8bb761785dc30dbc320869e1a00).zfill(114)

        self._run_448_test(message, d, expected_public_key, expected_sig)
