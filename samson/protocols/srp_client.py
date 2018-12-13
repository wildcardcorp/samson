from samson.utilities.math import modexp
from samson.utilities.bytes import Bytes
from samson.hashes.sha2 import SHA256


# http://srp.stanford.edu/design.html
# https://bnetdocs.org/document/24/nls-srp-protocol
# https://tools.ietf.org/html/rfc5054#
class SRPClient(object):
    """
    Secure Remote Password protocol client
    """

    MODP_1024 = 0xEEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3
    MODP_1536 = 0x9DEF3CAFB939277AB1F12A8617A47BBBDBA51DF499AC4C80BEEEA9614B19CC4D5F4F5F556E27CBDE51C6A94BE4607A291558903BA0D0F84380B655BB9A22E8DCDF028A7CEC67F0D08134B1C8B97989149B609E0BE3BAB63D47548381DBC5B1FC764E3F4B53DD9DA1158BFD3E2B9C8CF56EDF019539349627DB2FD53D24B7C48665772E437D6C7F8CE442734AF7CCB7AE837C264AE3A9BEB87F8A2FE9B8B5292E5A021FFF5E91479E8CE7A28C2442C6F315180F93499A234DCF76E3FED135F9BB
    MODP_2048 = 0xAC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73


    def __init__(self, identity: bytes, password: bytes, g: int=2, N: int=MODP_1024, hash_obj: object=SHA256(), a: int=None):
        """
        Parameters:
            identity  (bytes): Username.
            password  (bytes): Password.
            g           (int): Generator.
            N           (int): Prime modulus.
            hash_obj (object): Instantiated object with compatible hash interface.
            a           (int): Random private value.
        """
        self.a = a or Bytes.random(4).int() % N
        self.g = g
        self.A = modexp(g, self.a, N)
        self.identity = identity
        self.password = password
        self.N = N
        self.hash_obj = hash_obj
        self.k = hash_obj.hash(Bytes(N) + self.PAD(g)).int()



    def PAD(self, in_bytes: bytes) -> Bytes:
        """
        If a conversion is explicitly specified with the operator PAD(), the integer will first be implicitly converted, then the resultant byte-string will be left-padded with zeros (if necessary) until its length equals the implicitly-converted length of N.
        """
        return Bytes.wrap(in_bytes).zfill((self.N.bit_length() + 7) // 8)



    def make_request(self) -> (bytes, int):
        """
        Creates the initial client request.

        Returns:
            (bytes, int): Formatted as (identity, client's challenge `A`).
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
        uH = self.hash_obj.hash(self.PAD(self.A) + self.PAD(B)).int()
        xH = self.hash_obj.hash(salt + self.hash_obj.hash(self.identity + b':' + self.password)).int()

        p1 = (B - self.k * modexp(self.g, xH, self.N))
        p2 = (self.a + uH * xH)
        cS = modexp(p1, p2, self.N)

        cK = self.hash_obj.hash(Bytes(cS))
        return self.hash_obj.hash(cK + salt)



    def craft_malicious_request(self) -> (bytes, int):
        """
        Crafts a malicious request by setting the initial challenge parameter to zero.

        Returns:
            (bytes, int): Formatted as (identity, 0).
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
        cK = self.hash_obj.hash(b'\x00')
        return self.hash_obj.hash(cK + salt)
