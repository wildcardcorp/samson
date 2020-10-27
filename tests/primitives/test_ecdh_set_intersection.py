
from samson.utilities.bytes import Bytes
from samson.protocols.ecdh_set_intersection import ECDHSetIntersectionClient, ECDHSetIntersectionServer
from samson.math.algebra.curves.named import P256
from samson.hashes.sha2 import SHA256
import unittest


class ECDHSITestCase(unittest.TestCase):
    def test_ecdhsi(self):
        # Parameters
        hash_obj = SHA256()
        curve    = P256

        # Instantiate proto
        server = ECDHSetIntersectionServer(hash_obj, curve)
        client = ECDHSetIntersectionClient(hash_obj, curve)

        # Add elements to server
        passwords = [b'Spring2020!', b'mypassword123', b'l3Tme1n!'] + [Bytes.random(8) for _ in range(2048)]

        for password in passwords:
            server.add_element(password)


        # Perform proto
        assert client.check_element(b'Spring2020!', server)
        assert not client.check_element(b'Summer2020!', server)
