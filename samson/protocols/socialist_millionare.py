from samson.protocols.diffie_hellman import DiffieHellman
from samson.utilities.math import mod_inv
from samson.utilities.bytes import Bytes

class SocialistMillionare(object):
    """
    Zero-Knowledge Proof of a secret using Diffie-Hellman exchanges.
    """

    def __init__(self, h: int=2, p: int=DiffieHellman.MODP_1536, key: bytes=None, exp1: int=None, exp2: int=None, validate: bool=True):
        """
        Parameters:
            h         (int): Generator.
            p         (int): Prime modulus.
            key     (bytes): Secret.
            exp1      (int): First random exponent.
            exp2      (int): Second random exponent.
            validate (bool): Whether or not to validate challenges to prevent exploits.
        """
        self.h = h
        self.p = p
        self.key = Bytes.wrap(key).int() or Bytes.random(16).int()
        self.validate = validate

        # We do this explicitly with None so users can easily set these values to zero :)
        if exp1 is None:
            exp1 = Bytes.random(16).int()

        if exp2 is None:
            exp2 = Bytes.random(16).int()

        self.exp1 = exp1
        self.exp2 = exp2

        self.P_b = None

        self.P = None
        self.Q = None


    def __repr__(self):
        return f"<SocialistMillionare: key={self.key}, h={self.h}, p={self.p}, exp1={self.exp1}, exp2={self.exp2}, validate={self.validate}>"

    def __str__(self):
        return self.__repr__()



    def get_initial_challenge(self) -> (int, int):
        """
        Creates the initial Diffie-Hellman challenges.

        Returns:
            (int, int): The Diffie-Hellman challenges of the random exponents.
        """
        return pow(self.h, self.exp1, self.p), pow(self.h, self.exp2, self.p)


    def receive_initial_challenge(self, challenge: (int, int), r: int=None) -> (int, int):
        """
        Receives the Diffie-Hellman challenges and produces the next challenge parameters.

        Parameters:
            challenge ((int, int)): Challenge from peer.
            r                (int): Ephemeral random exponent.
        
        Returns:
            (int, int): P and Q values to send to its peer.
        """
        h_a1, h_a2 = challenge
        if self.validate:
            assert h_a1 != 1
            assert h_a2 != 1

        r = r or Bytes.random(16).int()
        g, R = pow(h_a1, self.exp1, self.p), pow(h_a2, self.exp2, self.p)

        self.P = pow(R, r, self.p)
        self.Q = (pow(self.h, r, self.p) * pow(g, self.key, self.p)) % self.p

        return self.P, self.Q


    def get_final_challenge(self, challenge: (int, int)) -> int:
        """
        Uses its peer's P and Q values to generate the final challenge.

        Parameters:
            challenge ((int, int)): P and Q values of peer's challenge.
        
        Returns:
            int: The final challenge.
        """
        self.P_b, Q_b = challenge
        if self.validate:
            assert self.P != self.P_b
            assert self.Q != Q_b

        return pow(Q_b * mod_inv(self.Q, self.p), self.exp2, self.p)


    def assert_correct(self, c_b: int) -> bool:
        """
        Processes the final challenge and asserts its correctness.

        Parameters:
            c_b (int): Peer's final challenge.
        
        Returns:
            bool: Whether or not the challenge was correct.
        """
        c = pow(c_b, self.exp2, self.p)
        return c == ((self.P * mod_inv(self.P_b, self.p)) % self.p)
