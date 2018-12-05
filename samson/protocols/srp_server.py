import hashlib
from samson.utilities.math import modexp
from samson.utilities.general import rand_bytes
from samson.utilities.encoding import int_to_bytes
from samson.protocols.srp_client import NIST_PRIME

class SRPServer(object):
    """
    Secure Remote Password protocol server
    """

    def __init__(self, g: int=2, k: int=3, N=NIST_PRIME):
        """
        Parameters:
            g          (int): Generator.
            k          (int): Multiplier.
            N          (int): Prime modulus.
        """
        self.g = g
        self.k = k
        self.N = N
        self.accounts = {}
        self.requests = {}
        self.salt = rand_bytes(4)

        self.b = int.from_bytes(rand_bytes(4), 'little') % N
        


    def create_account(self, identity: bytes, password: bytes):
        """
        Creates a new account entry with the server.

        Parameters:
            identity (bytes): Username.
            password (bytes): Password.
        """
        x = int.from_bytes(hashlib.sha256(self.salt + password).digest(), 'little')
        v = modexp(self.g, x, self.N)
        self.accounts[identity] = v


    
    def respond_with_challenge(self, identity: bytes, A: int) -> (bytes, int):
        """
        Receives the client's challenge and returns the server's challenge.

        Parameters:
            identity (bytes): Username.
            A          (int): Client's challenge.

        Returns:
            tuple: Formatted as (server salt, server's challenge `B`)
        """
        v = self.accounts[identity]
        B = self.k * v + modexp(self.g, self.b, self.N)
        self.requests[identity] = {'A': A, 'B': B}
        
        return self.salt, B



    def check_challenge(self, identity: bytes, client_hash: bytes) -> bool:
        """
        Checks if the client's challenge is correct.

        Parameters:
            identity    (bytes): Username.
            client_hash (bytes): Client's hash challenge.
        
        Returns:
            bool: Whether or not the challenge is correct.
        """
        request = self.requests[identity]
        v = self.accounts[identity]
        A = request['A']

        hex_A = int_to_bytes(A, 'little')
        print(hex_A)
        hex_B = int_to_bytes(request['B'], 'little')

        uH = int.from_bytes(hashlib.sha256(hex_A + hex_B).digest(), 'little')

        p1 = (A * modexp(v, uH, self.N))
        sS = modexp(p1, self.b, self.N)

        sK = hashlib.sha256(int_to_bytes(sS, 'little')).digest()
        return hashlib.sha256(sK + self.salt).digest() == client_hash