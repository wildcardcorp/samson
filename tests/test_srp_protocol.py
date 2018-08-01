from samson.protocols.srp_client import SRPClient
from samson.protocols.srp_server import SRPServer
import unittest


class SRPTestCase(unittest.TestCase):
    def setUp(self):
        self.username = b'daniel.cronce@wildcardcorp.com'
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
        client = SRPClient(b'daniel.cronce@wildcardcorp.com', b'Abracadabra')

        identity, A = client.craft_malicious_request()
        salt, _B = server.respond_with_challenge(identity, A)
        client_hash = client.craft_auth_bypass(salt)
        self.assertTrue(server.check_challenge(identity, client_hash))