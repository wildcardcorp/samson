from enum import Enum
from types import FunctionType

class PrimitiveType(Enum):
    CIPHER = 0
    HASH   = 1
    MAC    = 2
    KDF    = 3
    KEY_EXCHANGE = 4
    SIGNING = 5


class CipherType(Enum):
    NONE = 0
    NUMBER_THEORETICAL_CIPHER = 1
    STREAM_CIPHER = 2
    BLOCK_CIPHER  = 3


class SymmetryType(Enum):
    NONE       = 0
    SYMMETRIC  = 1
    ASYMMETRIC = 2


class ConstructionType(Enum):
    MERKLE_DAMGARD     = 0
    EVEN_MANSOUR       = 1
    FEISTEL_NETWORK    = 2
    MATYAS_MEYER_OSEAS = 3
    MIYAGUCHI_PRENEEL  = 4
    SPONGE             = 5
    SUBSTITUTION_PERMUTATION_NETWORK = 6
    ADD_ROTATE_XOR     = 7
    LFSR               = 8
    HASH_ITERATIVE_FRAMEWORK = 9
    DAVIES_MEYER       = 10


class SecurityProofType(Enum):
    NONE                  = 0
    DISCRETE_LOGARITHM    = 1
    SHORTEST_VECTOR       = 2
    INTEGER_FACTORIZATION = 3


class UsageType(Enum):
    GENERAL  = 0
    CELLULAR = 1
    WIRELESS = 2
    ACADEMIC = 3
    OTHER    = 4


class SizeType(Enum):
    NONE      = 0
    SINGLE    = 1
    RANGE     = 2
    ARBITRARY = 3
    DEPENDENT = 4


class EphemeralType(Enum):
    IV    = 0
    NONCE = 1
    KEY   = 2


class SizeSpec(object):
    def __init__(self, size_type: SizeType, sizes: list=None, typical: list=None, selector: FunctionType=None):
        self.size_type = size_type
        self.sizes     = sizes or []
        self.typical   = typical or []
        self.selector  = selector
        self.parent    = None


    def __repr__(self):
        return f"<SizeSpec: size_type={self.size_type}, sizes={self.sizes}, typical={self.typical}, parent={self.parent}>"

    def __str__(self):
        return self.__repr__()


    def __contains__(self, item):
        if self.size_type == SizeType.ARBITRARY:
            return True

        elif self.size_type == SizeType.RANGE:
            return item in self.sizes

        elif self.size_type == SizeType.SINGLE:
            return item == self.sizes

        elif self.size_type == SizeType.DEPENDENT:
            size = self.selector(self.parent)
            if type(size) is SizeSpec:
                return item in size
            else:
                return item == size

        else:
            raise ValueError("This shouldn't be possible. Is 'size_type' not SizeType?")


class EphemeralSpec(object):
    def __init__(self, ephemeral_type: EphemeralType, size: SizeSpec):
        self.ephemeral_type = ephemeral_type
        self.size = size


    def __repr__(self):
        return f"<EphemeralSpec: ephemeral_type={self.ephemeral_type}, size={self.size}>"

    def __str__(self):
        return self.__repr__()