from samson.kdfs.scrypt import Scrypt
from samson.utilities.bytes import Bytes
import unittest

# https://tools.ietf.org/html/rfc7914#section-12
class ScryptTestCase(unittest.TestCase):
    def _run_test(self, password, salt, N, p, r, expected_derived):
        scrypt = Scrypt(cost=N, parallelization_factor=p, block_size_factor=r, desired_len=len(expected_derived))
        derived = scrypt.derive(password, salt)

        self.assertEqual(derived, expected_derived)



    def test_vec0(self):
        password         = Bytes(b'')
        salt             = Bytes(b'')
        p                = 1
        r                = 1
        N                = 16
        expected_derived = Bytes(0x77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906)

        self._run_test(password, salt, N, p, r, expected_derived)


    def test_vec1(self):
        password         = Bytes(b'password')
        salt             = Bytes(b'NaCl')
        p                = 16
        r                = 8
        N                = 1024
        expected_derived = Bytes(0xfdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640)

        self._run_test(password, salt, N, p, r, expected_derived)


    def test_vec2(self):
        password         = Bytes(b'pleaseletmein')
        salt             = Bytes(b'SodiumChloride')
        p                = 1
        r                = 8
        N                = 16384
        expected_derived = Bytes(0x7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887)

        self._run_test(password, salt, N, p, r, expected_derived)


    # Takes way too long
    # def test_vec3(self):
    #     password         = Bytes(b'pleaseletmein')
    #     salt             = Bytes(b'SodiumChloride')
    #     p                = 1
    #     r                = 8
    #     N                = 1048576
    #     expected_derived = Bytes(0x2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4)

    #     self._run_test(password, salt, N, p, r, expected_derived)


    # Manualy generated
    def test_vec4(self):
        password         = Bytes(b"correct horse battery staple")
        salt             = Bytes(b"seasalt")
        p                = 1
        r                = 1
        N                = 1024
        expected_derived = Bytes(0x8dc98cddcf52dd725d52b913f7bf8386fa44e1406795aa661487f434007dff1680be6baddd724659316f7ff4663174a7a4ead1c95d5175cf284ac9ae8703e1fba445e4a6c51dc215cb0b590e30b62c55af7ee950ac0317e8b2c94a5f85a3753f43347eb9887cc7a5e6048e4a9468efeefd346b9e2c95214cabda3ac410b9660c9d0271210b49872608af567fc4a06bcfaf9c4a50628792e2149cf2d949ebf0f714bb124d72bd3c6ab816e8bf703dbbb1ae051d74d4f9ed2b6a2ca4949340a07fce7a9e26c26469807f7f6cb3a374fe1b0bd1fcfb4fbd5e71adf3d66f559208855fe2c35ae00d006c39341de24b45fc279a746456cfb5313bde9b2db431288d05)

        self._run_test(password, salt, N, p, r, expected_derived)
