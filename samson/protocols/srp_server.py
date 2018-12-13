from samson.utilities.math import modexp
from samson.protocols.srp_client import SRPClient
from samson.hashes.sha2 import SHA256
from samson.utilities.bytes import Bytes

class SRPServer(object):
    """
    Secure Remote Password protocol server
    """

    def __init__(self, g: int=2, N: int=SRPClient.MODP_1024, hash_obj: object=SHA256(), b: int=None):
        """
        Parameters:
            g           (int): Generator.
            N           (int): Prime modulus.
            hash_obj (object): Instantiated object with compatible hash interface
            b           (int): Random private value.
        """
        self.g = g
        self.N = N
        self.hash_obj = hash_obj

        self.accounts = {}
        self.requests = {}
        self.salt = Bytes.random(4)

        self.b = b or Bytes.random(4).int() % N
        self.k = hash_obj.hash(Bytes(N) + self.PAD(g)).int()


    def PAD(self, in_bytes: bytes) -> Bytes:
        """
        If a conversion is explicitly specified with the operator PAD(), the integer will first be implicitly converted, then the resultant byte-string will be left-padded with zeros (if necessary) until its length equals the implicitly-converted length of N.
        """
        return Bytes.wrap(in_bytes).zfill((self.N.bit_length() + 7) // 8)




    def create_account(self, identity: bytes, password: bytes):
        """
        Creates a new account entry with the server.

        Parameters:
            identity (bytes): Username.
            password (bytes): Password.
        """
        # x = self.hash_obj.hash(self.salt + password).int()
        x = self.hash_obj.hash(self.salt + self.hash_obj.hash(identity + b':' + password)).int()
        v = modexp(self.g, x, self.N)
        self.accounts[identity] = v



    def respond_with_challenge(self, identity: bytes, A: int) -> (bytes, int):
        """
        Receives the client's challenge and returns the server's challenge.

        Parameters:
            identity (bytes): Username.
            A          (int): Client's challenge.

        Returns:
            (bytes, int): Formatted as (server salt, server's challenge `B`)
        """
        v = self.accounts[identity]
        B = (self.k * v + modexp(self.g, self.b, self.N)) % self.N
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

        uH = self.hash_obj.hash(self.PAD(A) + self.PAD(request['B'])).int()

        p1 = (A * modexp(v, uH, self.N))
        sS = modexp(p1, self.b, self.N)

        sK = self.hash_obj.hash(Bytes(sS))
        return self.hash_obj.hash(sK + self.salt) == client_hash
