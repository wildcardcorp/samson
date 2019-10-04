
from samson.core.metadata import SizeSpec, SizeType, SymmetryType, EphemeralType, SecurityProofType, UsageType, ConstructionType, PrimitiveType, CipherType
from samson.ace.decorators import has_exploit, creates_constraint
from samson.ace.exploit import KeyPossession, PlaintextPossession
from samson.ace.constraints import EncryptedConstraint
from samson.utilities.bytes import Bytes
from copy import deepcopy
from abc import abstractmethod

"""
This module's purpose is to create a unified, concise, and machine-readable description of samson's primitives.

Each class provides:
    * A uniform interface based on the usage of the primitive type
    * A generic description of primitive types by mapping their properties to samson's Primitive Specification Metalanguage (PSML)
    * A best effort description of non-uniform properties that can be overriden
"""

class Primitive(object):
    CONSTRUCTION_TYPES = []
    USAGE_TYPE         = UsageType.GENERAL
    SECURITY_PROOF     = SecurityProofType.NONE
    SYMMETRY_TYPE      = SymmetryType.NONE
    CIPHER_TYPE        = CipherType.NONE

    def __init__(self):
        for attr in [attr for attr in dir(self) if attr in ['KEY_SIZE', 'OUTPUT_SIZE', 'INPUT_SIZE', 'BLOCK_SIZE']]:
            if getattr(self, attr).size_type == SizeType.DEPENDENT:
                setattr(self, attr, deepcopy(getattr(self, attr)))
                getattr(self, attr).parent = self
        

@has_exploit(KeyPossession)
@creates_constraint(EncryptedConstraint())
class EncryptionAlg(Primitive):
    PRIMITIVE_TYPE = PrimitiveType.CIPHER

    @abstractmethod
    def encrypt(self, *args, **kwargs):
        pass

    @abstractmethod
    def decrypt(self, *args, **kwargs):
        pass


@has_exploit(PlaintextPossession)
@has_exploit(KeyPossession)
class MAC(Primitive):
    PRIMITIVE_TYPE = PrimitiveType.MAC
    KEY_SIZE       = SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda cipher: cipher.KEY_SIZE)
    SYMMETRY_TYPE  = SymmetryType.SYMMETRIC
    INPUT_SIZE     = SizeSpec(size_type=SizeType.ARBITRARY)
    OUTPUT_SIZE    = SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda cipher: cipher.KEY_SIZE)

    @abstractmethod
    def generate(self, *args, **kwargs):
        pass

    def verify(self, message: bytes, signature: bytes) -> bool:
        return self.generate(message) == signature


class Hash(Primitive):
    PRIMITIVE_TYPE     = PrimitiveType.HASH
    INPUT_SIZE         = SizeSpec(size_type=SizeType.ARBITRARY)
    CONSTRUCTION_TYPES = [ConstructionType.MERKLE_DAMGARD]

    @abstractmethod
    def hash(self, *args, **kwargs):
        pass


class NumberTheoreticalAlg(Primitive):
    SYMMETRY_TYPE  = SymmetryType.ASYMMETRIC
    PRIMITIVE_TYPE = PrimitiveType.CIPHER
    CIPHER_TYPE    = CipherType.NUMBER_THEORETICAL_CIPHER
    KEY_SIZE       = SizeSpec(size_type=SizeType.ARBITRARY, typical=[1024, 2048, 4096])
    INPUT_SIZE     = SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda cipher: cipher.KEY_SIZE)
    OUTPUT_SIZE    = SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda cipher: cipher.KEY_SIZE) 
    SECURITY_PROOF = SecurityProofType.DISCRETE_LOGARITHM 


class SignatureAlg(NumberTheoreticalAlg):
    PRIMITIVE_TYPE = PrimitiveType.SIGNING
    KEY_SIZE       = SizeSpec(size_type=SizeType.ARBITRARY, typical=[160, 224, 256])
    CIPHER_TYPE    = CipherType.NONE


class KeyExchangeAlg(Primitive):
    PRIMITIVE_TYPE = PrimitiveType.KEY_EXCHANGE
    SYMMETRY_TYPE  = SymmetryType.ASYMMETRIC
    SECURITY_PROOF = SecurityProofType.DISCRETE_LOGARITHM
    KEY_SIZE       = SizeSpec(size_type=SizeType.ARBITRARY, typical=[1024, 2048, 4096])
    INPUT_SIZE     = SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda cipher: cipher.KEY_SIZE)


class StreamCipher(EncryptionAlg):
    SYMMETRY_TYPE = SymmetryType.SYMMETRIC
    CIPHER_TYPE   = CipherType.STREAM_CIPHER
    KEY_SIZE      = SizeSpec(size_type=SizeType.RANGE, sizes=[128, 256])
    INPUT_SIZE    = SizeSpec(size_type=SizeType.ARBITRARY)
    OUTPUT_SIZE   = SizeSpec(size_type=SizeType.ARBITRARY)
    BLOCK_SIZE    = SizeSpec(size_type=SizeType.SINGLE, sizes=1)

    def encrypt(self, plaintext: bytes) -> Bytes:
        return self.generate(len(plaintext)) ^ plaintext

    def decrypt(self, ciphertext: bytes) -> Bytes:
        return self.encrypt(ciphertext)


class BlockCipher(EncryptionAlg):
    SYMMETRY_TYPE      = SymmetryType.SYMMETRIC
    CIPHER_TYPE        = CipherType.BLOCK_CIPHER
    CONSTRUCTION_TYPES = [ConstructionType.FEISTEL_NETWORK]
    KEY_SIZE           = SizeSpec(size_type=SizeType.RANGE, sizes=[128, 192, 256], typical=[128, 256])
    BLOCK_SIZE         = SizeSpec(size_type=SizeType.SINGLE, sizes=128)
    INPUT_SIZE         = SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda cipher: cipher.BLOCK_SIZE)
    OUTPUT_SIZE        = SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda cipher: cipher.BLOCK_SIZE)


class BlockCipherMode(EncryptionAlg):
    SYMMETRY_TYPE = SymmetryType.SYMMETRIC
    KEY_SIZE      = SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda mode: mode.encryptor)
    INPUT_SIZE    = SizeSpec(size_type=SizeType.ARBITRARY)
    OUTPUT_SIZE   = SizeSpec(size_type=SizeType.ARBITRARY)
    BLOCK_SIZE    = SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda mode: mode.encryptor)

