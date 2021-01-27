from samson.utilities.bytes import Bytes
from samson.core.primitives import MAC, Primitive
from samson.core.metadata import FrequencyType, UsageType
from samson.ace.decorators import register_primitive


@register_primitive()
class Michael(MAC):
    """
    References:
        "A Note on the Fragility of the 'Michael' Message Integrity Code"
    """

    USAGE_FREQUENCY = FrequencyType.UNUSUAL
    USAGE_TYPE      = UsageType.WIRELESS


    def __init__(self, key: bytes):
        Primitive.__init__(self)
        self.key = Bytes.wrap(key).zfill(8).change_byteorder('little')


    @staticmethod
    def ADD32(l: Bytes, r: Bytes) -> Bytes:
        return Bytes((l.int() + r.int()) % 2**32, 'little').zfill(4)


    @staticmethod
    def SUB32(l: Bytes, r: Bytes) -> Bytes:
        return Bytes((l.int() - r.int()) % 2**32, 'little').zfill(4)


    @staticmethod
    def XSWAP(l: Bytes) -> Bytes:
        return Bytes([l[1], l[0], l[3], l[2]], 'little')


    @staticmethod
    def b(l: Bytes, r: Bytes) -> (Bytes, Bytes):
        r ^= l.lrot(17)
        l  = Michael.ADD32(l, r)
        r ^= Michael.XSWAP(l)
        l  = Michael.ADD32(l, r)
        r ^= l.lrot(3)
        l  = Michael.ADD32(l, r)
        r ^= l.rrot(2)
        l  = Michael.ADD32(l, r)

        return l, r


    @staticmethod
    def b_inv(l: Bytes, r: Bytes) -> (Bytes, Bytes):
        l  = Michael.SUB32(l, r)
        r ^= l.rrot(2)
        l  = Michael.SUB32(l, r)
        r ^= l.lrot(3)
        l  = Michael.SUB32(l, r)
        r ^= Michael.XSWAP(l)
        l  = Michael.SUB32(l, r)
        r ^= l.lrot(17)

        return l, r


    @staticmethod
    def pad(message: Bytes) -> Bytes:
        return (message + b'\x5a' + b'\x00'*4).pad_congruent_right(4).change_byteorder('little')


    def generate(self, message: bytes, pad: bool=True) -> Bytes:
        """
        Generates the Michael MIC of `message`.

        Parameters:
            message (bytes): Message to authenticate.
            pad      (bool): Whether or not to apply the Michael padding to the plaintext.

        Returns:
            Bytes: MIC of `message`.
        """
        message = Bytes.wrap(message)

        if pad:
            message = Michael.pad(message)

        l, r = self.key.chunk(4)
        for chunk in message.chunk(4):
            l   ^= chunk
            l, r = Michael.b(l, r)

        return l.zfill(4) + r.zfill(4)


    @staticmethod
    def crack(message: bytes, mic: bytes, pad: bool=True) -> Bytes:
        """
        Inverts the Michael function and cracks the key.

        Parameters:
            message (bytes): Message.
            mic     (bytes): Michael MIC of `message`.
            pad      (bool): Whether or not to apply the Michael padding to the plaintext.

        Returns:
            Michael: Cracked Michael instance.

        Examples:
            >>> k   = Bytes(0xd55e100510128986)
            >>> pt  = Bytes.random(50)
            >>> m   = Michael(k)
            >>> mic = m.generate(pt)
            >>> Michael.crack(pt, mic).key == k
            True

        """
        message = Bytes.wrap(message)
        mic     = Bytes.wrap(mic).zfill(8)
        l, r    = mic.chunk(4)

        if pad:
            message = Michael.pad(message)

        for chunk in message.chunk(4)[::-1]:
            l, r = Michael.b_inv(l, r)
            l   ^= chunk

        return Michael(l.zfill(4) + r.zfill(4))
