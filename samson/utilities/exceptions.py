from enum import Enum

class NotInvertibleException(Exception):
    def __init__(self, msg: str, parameters: dict):
        self.parameters = parameters
        super().__init__(msg)


class SearchspaceExhaustedException(Exception):
    pass


class CoercionException(Exception):
    pass


class ProbabilisticFailureException(Exception):
    pass


class NoSolutionException(Exception):
    pass


class OracleException(Exception):
    pass


class InvalidSignatureException(Exception):
    pass


class DecryptionValidationStep(Enum):
    CIPHERTEXT = 0
    MAC        = 1
    PADDING    = 2
    PLAINTEXT  = 3

    def __lt__(self, other):
        return self.value < other.value

    def __gt__(self, other):
        return self.value > other.value

    def __le__(self, other):
        return self.value <= other.value

    def __ge__(self, other):
        return self.value >= other.value



class DecryptionException(OracleException):
    DECRYPT_STEP = None


class CiphertextLengthException(DecryptionException):
    DECRYPT_STEP = DecryptionValidationStep.CIPHERTEXT


class InvalidMACException(DecryptionException, InvalidSignatureException):
    DECRYPT_STEP = DecryptionValidationStep.MAC


class InvalidPaddingException(DecryptionException):
    DECRYPT_STEP = DecryptionValidationStep.PADDING


class InvalidPlaintextException(DecryptionException):
    DECRYPT_STEP = DecryptionValidationStep.PLAINTEXT
