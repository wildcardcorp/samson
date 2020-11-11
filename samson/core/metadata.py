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
    WEGMAN_CARTER      = 11


class SecurityProofType(Enum):
    NONE                  = 0
    DISCRETE_LOGARITHM    = 1
    SHORTEST_VECTOR       = 2
    INTEGER_FACTORIZATION = 3
    INFORMATION_THEORETIC = 4


class UsageType(Enum):
    GENERAL  = 0
    CELLULAR = 1
    WIRELESS = 2
    ACADEMIC = 3
    OTHER    = 4


class SizeType(Enum):
    """
    SizeTypes determine the behavior of the SizeSpec.

    SINGLE    - only accept one value. Sets "sizes" to an integer.
    RANGE     - accept any value in "sizes". "sizes" is iterable. Can use "typical" to denote typical values.
    ARBITRARY - accept any size. "sizes" is unused. Can use "typical" to denote typical values.
    DEPENDENT - size is dependent on another value that can only be resolved on instantiation.
    """
    NONE      = 0
    SINGLE    = 1
    RANGE     = 2
    ARBITRARY = 3
    DEPENDENT = 4


class EphemeralType(Enum):
    """
    EphemeralTypes determine the usage and consequences of ephemeral values.

    IV    - reuse may result in distinguishing attacks (e.g. block A has the same plaintext as block B).
    NONCE - reuse may result in plaintext recovery attacks or potentially worse.
    KEY   - ephemeral is secret and reuse may result in key recovery attacks.
    """
    IV    = 0
    NONCE = 1
    KEY   = 2


class IORelationType(Enum):
    """
    IORelationTypes determine the relation between input and output sizes.

    EQUAL     - input and output size are always equal.
    FIXED     - output size is fixed.
    ARBITRARY - input and output size can be arbitrarily picked.
    """
    EQUAL     = 0
    FIXED     = 1
    ARBITRARY = 2


class MalleabilityType(Enum):
    """
    MalleabilityTypes determine the malleability properties of the output.

    NONE           - the output is not malleable.
    BITWISE        - the output can be manipulated at a bit level.
    ADDITION       - the output is homomorphic under addition.
    MULTIPLICATION - the output is homomorphic under multiplication.
    """
    NONE           = 0
    BITWISE        = 1
    ADDITION       = 2
    MULTIPLICATION = 3


class FrequencyType(Enum):
    """
    FrequencyTypes determine the frequency of the value of a property.

    NEGLIGIBLE - value is almost never seen.
    UNUSUAL    - value occurs less than average.
    NORMAL     - value occurs with average frequency.
    OFTEN      - value occurs more than average.
    PROLIFIC   - value is almost always seen.
    """
    NEGLIGIBLE = 0
    UNUSUAL    = 1
    NORMAL     = 2
    OFTEN      = 3
    PROLIFIC   = 4



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
            result = True

        elif self.size_type == SizeType.RANGE:
            if type(item) is list:
                result = all([i in self.sizes for i in item])
            else:
                result = item in self.sizes

        elif self.size_type == SizeType.SINGLE:
            result = item == self.sizes

        elif self.size_type == SizeType.DEPENDENT:
            if self.parent is None:
                return False

            size = self.selector(self.parent)

            if type(size) is SizeSpec:
                result = item in size
            else:
                result = item == size

        else:
            raise ValueError("This shouldn't be possible. Is 'size_type' not SizeType?")

        return result


    def __eq__(self, other):
        return type(other) == type(self) and self.size_type == other.size_type and self.sizes == other.sizes


    def __lt__(self, other):
        if type(other) is int:
            if self.size_type == SizeType.ARBITRARY:
                result = False

            elif self.size_type == SizeType.RANGE:
                result = other > sorted(self.sizes)[-1]

            elif self.size_type == SizeType.SINGLE:
                result = other > self.sizes

            elif self.size_type == SizeType.DEPENDENT:
                if self.parent is None:
                    return False

                size   = self.selector(self.parent)
                result = other > size

            return result
        else:
            raise NotImplementedError()




class EphemeralSpec(object):
    def __init__(self, ephemeral_type: EphemeralType, size: SizeSpec):
        self.ephemeral_type = ephemeral_type
        self.size = size


    def __repr__(self):
        return f"<EphemeralSpec: ephemeral_type={self.ephemeral_type}, size={self.size}>"

    def __str__(self):
        return self.__repr__()


    def __eq__(self, other):
        return type(other) == type(self) and self.ephemeral_type == other.ephemeral_type and self.size == other.size



class FrequencySpec(object):
    def __init__(self, frequency_type: FrequencyType, value: object=None):
        self.frequency_type = frequency_type
        self.value = value


    def __repr__(self):
        return f"<FrequencySpec: frequency_type={self.frequency_type}, value={self.value}>"

    def __str__(self):
        return self.__repr__()


    def __eq__(self, other):
        return type(other) == type(self) and self.frequency_type == other.frequency_type and self.value == other.value
