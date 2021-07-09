from samson.protocols.srp_client import SRPClient
from samson.protocols.srp_server import SRPServer
from samson.utilities.bytes import Bytes
from samson.hashes.sha1 import SHA1
import unittest


class SRPTestCase(unittest.TestCase):
    def setUp(self):
        self.username = b'dani.cronce@wildcardcorp.com'
        self.password = b'P@ssw0rd'


    def test_auth_success(self):
        # Create server and setup account
        server = SRPServer()
        server.create_account(self.username, self.password)

        # Create client
        client = SRPClient(self.username, self.password)

        # Execute authentication protocol
        identity, A = client.make_request()
        salt, B = server.respond_with_challenge(identity, A)
        client_hash = client.perform_challenge(salt, B)

        self.assertTrue(server.check_challenge(identity, client_hash))


    def test_auth_fail(self):
        # Create server and setup account
        server = SRPServer()
        server.create_account(self.username, self.password)

        # Create client
        client = SRPClient(self.username, b'Not the same pass!')

        # Execute authentication protocol
        identity, A = client.make_request()
        salt, B = server.respond_with_challenge(identity, A)
        client_hash = client.perform_challenge(salt, B)

        self.assertFalse(server.check_challenge(identity, client_hash))


    def test_auth_bypass(self):
        # Create server and setup account
        server = SRPServer()
        server.create_account(self.username, self.password)

        # Create client
        client = SRPClient(b'dani.cronce@wildcardcorp.com', b'Abracadabra')

        identity, A = client.craft_malicious_request()
        salt, _B = server.respond_with_challenge(identity, A)
        client_hash = client.craft_auth_bypass(salt)

        self.assertTrue(server.check_challenge(identity, client_hash))


    def _run_test(self, identity, password, salt, N, g, a, b, expected_A, expected_B, expected_v, expected_k):
        hash_obj = SHA1()
        server = SRPServer(N=N, g=g, b=b, hash_obj=hash_obj)
        server.salt = salt
        server.create_account(identity=identity, password=password)

        # Create client
        client = SRPClient(identity=identity, password=password, N=N, g=g, a=a, hash_obj=hash_obj)

        # Execute authentication protocol
        identity, A = client.make_request()
        salt, B = server.respond_with_challenge(identity, A)
        client_hash = client.perform_challenge(salt, B)

        self.assertEqual(A, expected_A)
        self.assertEqual(B, expected_B)
        self.assertEqual(server.accounts[identity], expected_v)
        self.assertEqual(server.k, expected_k)
        self.assertEqual(client.k, expected_k)

        self.assertTrue(server.check_challenge(identity, client_hash))



    # https://tools.ietf.org/html/rfc5054#appendix-B
    def test_vec0(self):
        I = b"alice"
        P = b"password123"
        s = Bytes(0xBEB25379D1A8581EB5A727673A2441EE)
        N, g = SRPClient.MODP_1024, 2
        k = 0x7556AA045AEF2CDD07ABAF0F665C3E818913186F
        v = 0x7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D8129BADA1F1822223CA1A605B530E379BA4729FDC59F105B4787E5186F5C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78E955A5E29E7AB245DB2BE315E2099AFB
        a = 0x60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393
        b = 0xE487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20
        A = 0x61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC44352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEAB349EF5D76988A3672FAC47B0769447B
        B = 0xBD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC996C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAEEB4012B7D7665238A8E3FB004B117B58

        self._run_test(I, P, s, N, g, a, b, A, B, v, k)
