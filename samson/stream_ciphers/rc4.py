from samson.utilities.bytes import Bytes
from samson.core.primitives import StreamCipher, Primitive
from samson.ace.decorators import has_exploit
from samson.ace.exploit import BitlevelMalleability
from samson.attacks.rc4_prepend_attack import RC4PrependAttack
from samson.core.metadata import SizeType, SizeSpec, FrequencyType
from samson.ace.decorators import register_primitive

@has_exploit(RC4PrependAttack)
@has_exploit(BitlevelMalleability)
@register_primitive()
class RC4(StreamCipher):
    """
    Rivest Cipher 4 (RC4)

    Broken stream ciphers with large, initial-keystream biases.
    """

    KEY_SIZE        = SizeSpec(size_type=SizeType.RANGE, sizes=range(40, 2041))
    USAGE_FREQUENCY = FrequencyType.UNUSUAL


    def __init__(self, key: bytes):
        """
        Parameters:
            key (bytes): Key (40-2040 bits).
        """
        Primitive.__init__(self)
        self.key = key
        self.S = self.key_schedule(key)
        self.i = 0
        self.j = 0



    def key_schedule(self, key: bytes) -> list:
        """
        Prepares the internal state using the key.

        Parameters:
            key (bytes): Key.
        
        Returns:
            list: State parameter `S`.
        """
        key_length = len(key)
        S = []
        for i in range(256):
            S.append(i)

        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % key_length]) % 256
            S[i], S[j] = S[j], S[i]

        return S


    def generate(self, length: int) -> Bytes:
        """
        Generates `length` of keystream.

        Parameters:
            length (int): Desired length of keystream in bytes.
        
        Returns:
            Bytes: Keystream.
        """
        keystream = Bytes(b'')

        for _ in range(length):
            self.i = (self.i + 1) % 256
            self.j = (self.j + self.S[self.i]) % 256
            self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
            keystream += bytes([self.S[(self.S[self.i] + self.S[self.j]) % 256]])

        return keystream
