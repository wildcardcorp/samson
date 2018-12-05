import hashlib
from samson.utilities.math import modexp
from samson.utilities.general import rand_bytes
from samson.utilities.encoding import int_to_bytes
from samson.utilities.bytes import Bytes

NIST_PRIME = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF

# http://srp.stanford.edu/design.html
# https://bnetdocs.org/document/24/nls-srp-protocol
# TODO: Is SRP little endian or big endian?
class SRPClient(object):
    """
    Secure Remote Password protocol client
    """

    def __init__(self, identity: bytes, password: bytes, g: int=2, k: int=3, N: int=NIST_PRIME):
        """
        Parameters:
            identity (bytes): Username.
            password (bytes): Password.
            g          (int): Generator.
            k          (int): Multiplier.
            N          (int): Prime modulus.
        """
        self.a = int.from_bytes(rand_bytes(4), 'little') % N
        self.g = g
        self.k = k
        self.A = modexp(g, self.a, N)
        self.identity = identity
        self.password = password
        self.N = N

    
    def make_request(self) -> (bytes, int):
        """
        Creates the initial client request.

        Returns:
            tuple: Formatted as (identity, client's challenge `A`).
        """
        return self.identity, self.A



    def perform_challenge(self, salt: bytes, B: int) -> Bytes:
        """
        Performs server challenge.

        Parameters:
            salt  (bytes): Salt from server.
            B       (int): Server's challenge.
        
        Returns:
            Bytes: Challenge bytes to send to server.
        """
        hex_A = int_to_bytes(self.A, 'little')
        hex_B = int_to_bytes(B, 'little')

        uH = int.from_bytes(hashlib.sha256(hex_A + hex_B).digest(), 'little')
        xH = int.from_bytes(hashlib.sha256(salt + self.password).digest(), 'little')

        p1 = (B - self.k * modexp(self.g, xH, self.N))
        p2 = (self.a + uH * xH)
        cS = modexp(p1, p2, self.N)

        cK = hashlib.sha256(int_to_bytes(cS, 'little')).digest()
        return Bytes(hashlib.sha256(cK + salt).digest())



    def craft_malicious_request(self) -> (bytes, int):
        """
        Crafts a malicious request by setting the initial challenge parameter to zero.

        Returns:
            tuple: Formatted as (identity, 0).
        """
        return self.identity, 0


    def craft_auth_bypass(self, salt: bytes) -> Bytes:
        """
        Crafts the authentication bypass challenge. Only works if server accepted the initial malicious request.

        Parameters:
            salt (bytes): Salt from server.

        Returns:
            Bytes: Challenge bytes to send to server.
        """
        cK = hashlib.sha256(b'\x00' * 1).digest()
        return Bytes(hashlib.sha256(cK + salt).digest())