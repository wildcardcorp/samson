from samson.utilities.bytes import Bytes
from samson.encoding.pgp.core.constants import PGPPublicKeyAlgo
from enum import Enum

# https://tools.ietf.org/html/rfc4880#section-4.2.2
class PGPLength(object):
    def __init__(self, length):
        self.length = length


    def __repr__(self):
        return f"<PGPLength: length={self.length}>"

    def __str__(self):
        return self.__repr__()


    def encode(self) -> bytes:
        if self.length < 192:
            return Bytes(self.length)

        elif self.length < 8383:
            # The constant was calculated algebraically from the respective two-byte decode function
            return Bytes(self.length + 48960)

        else:
            return Bytes(0xFF) + Bytes(self.length).zfill(4)



    @staticmethod
    def decode(len_bytes: bytes) -> object:
        encoding_len = len(len_bytes)

        if encoding_len == 1:
            length = Bytes.wrap(len_bytes).int()

        elif encoding_len == 2:
            length = ((len_bytes[0] - 192) << 8) + len_bytes[1] + 192

        else:
            length = (len_bytes[1] << 24) + (len_bytes[2] << 16) + (len_bytes[3] << 8) + len_bytes[4]

        return PGPLength(length)



class PGPPacketTag(Enum):
    PUBLIC_KEY_ENC_SESSION_KEY = 1
    SIGNATURE       = 2
    SYMMETRIC_KEY_ENC_SESSION_KEY = 3
    ONE_PASS_SIG    = 4
    SECRET_KEY      = 5
    PUBLIC_KEY      = 6
    SECRET_SUBKEY   = 7
    COMPRESSED_DATA = 8
    SYMMETRICALLY_ENC_DATA = 9
    MARKER          = 10
    LITERAL_DATA    = 11
    TRUST_PACKET    = 12
    USER_ID         = 13
    PUBLIC_SUBKEY   = 14
    USER_ATTRIB     = 17
    SYMMETRICALLY_ENC_AND_INTEGRITY_PROTECTED_DATA = 18
    MODIFICATION_DETECTION_CODE = 19



# https://tools.ietf.org/html/rfc4880#section-4
class PGPPacket(object):
    def __init__(self, tag):
        self.tag = tag



class PGPPublicKeyPacket(object):
    def __init__(self, version: int, timestamp: int, pub_key_algo: PGPPublicKeyAlgo):
        self.version      = version
        self.timestamp    = timestamp
        self.pub_key_algo = pub_key_algo


    def __repr__(self):
        return f"<PGPPublicKeyPacket: version={self.version}, timestamp={self.timestamp}, pub_key_algo={self.pub_key_algo}>"

    def __str__(self):
        return self.__repr__()



class PGPRSAPublicKeyPacket(PGPPublicKeyPacket):
    def __init__(self, version: int, timestamp: int, n: int, e: int):
        super().__init__(version, timestamp, PGPPublicKeyAlgo.RSA_ENC)
        self.n = n
        self.e = e


    def __repr__(self):
        return f"<PGPRSAPublicKeyPacket: version={self.version}, timestamp={self.timestamp}, n={self.n}, e={self.e}>"

    def __str__(self):
        return self.__repr__()


    def encode(self) -> bytes:

        pass
