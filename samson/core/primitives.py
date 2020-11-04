from samson.core.metadata import SizeSpec, SizeType, SymmetryType, EphemeralType, EphemeralSpec, SecurityProofType, UsageType, ConstructionType, PrimitiveType, CipherType, IORelationType, FrequencyType
from samson.ace.decorators import has_exploit, creates_constraint
from samson.ace.exploit import KeyPossession, PlaintextPossession
from samson.ace.constraints import EncryptedConstraint
from samson.utilities.bytes import Bytes
from samson.utilities.exceptions import CiphertextLengthException, InvalidMACException
from samson.core.base_object import BaseObject
from copy import deepcopy
from abc import abstractmethod

"""
This module's purpose is to create a unified, concise, and machine-readable description of samson's primitives.

Each class provides:
    * A uniform interface based on the usage of the primitive type
    * A generic description of primitive types by mapping their properties to samson's Primitive Specification Language (PSL)
    * A best effort description of non-uniform properties that can be overriden
"""

# https://stackoverflow.com/questions/128573/using-property-on-classmethods
class classproperty(object):

    def __init__(self, fget):
        self.fget = fget

    def __get__(self, owner_self, owner_cls):
        return self.fget(owner_cls)


class Primitive(BaseObject):
    CONSTRUCTION_TYPES = []
    USAGE_TYPE         = UsageType.GENERAL
    USAGE_FREQUENCY    = FrequencyType.NEGLIGIBLE
    SECURITY_PROOF     = SecurityProofType.NONE
    SYMMETRY_TYPE      = SymmetryType.NONE
    CIPHER_TYPE        = CipherType.NONE
    IO_RELATION_TYPE   = IORelationType.FIXED

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
    BLOCK_SIZE     = SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda cipher: cipher.BLOCK_SIZE)
    OUTPUT_SIZE    = SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda cipher: cipher.OUTPUT_SIZE)

    @abstractmethod
    def generate(self, *args, **kwargs):
        pass

    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Verifies `message` and `signature` by regenerating the signature.

        Parameters:
            message   (bytes): Message to verify.
            signature (bytes): Alleged signature of `message`.
        
        Returns:
            bool: Whether or not the signature matched.
        """
        from samson.utilities.runtime import RUNTIME
        return RUNTIME.compare_bytes(self.generate(message), signature)


class KDF(Primitive):
    PRIMITIVE_TYPE = PrimitiveType.KDF
    INPUT_SIZE     = SizeSpec(size_type=SizeType.ARBITRARY)
    BLOCK_SIZE     = SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda cipher: cipher.hash_obj.BLOCK_SIZE)
    OUTPUT_SIZE    = SizeSpec(size_type=SizeType.ARBITRARY)


    @abstractmethod
    def derive(self, *args, **kwargs):
        pass


class Hash(Primitive):
    PRIMITIVE_TYPE     = PrimitiveType.HASH
    INPUT_SIZE         = SizeSpec(size_type=SizeType.ARBITRARY)
    CONSTRUCTION_TYPES = [ConstructionType.MERKLE_DAMGARD]

    @classproperty
    def BLOCK_SIZE(cls):
        return cls.OUTPUT_SIZE

    @abstractmethod
    def hash(self, *args, **kwargs):
        pass


class NumberTheoreticalAlg(Primitive):
    SYMMETRY_TYPE  = SymmetryType.ASYMMETRIC
    PRIMITIVE_TYPE = PrimitiveType.CIPHER
    CIPHER_TYPE    = CipherType.NUMBER_THEORETICAL_CIPHER
    KEY_SIZE       = SizeSpec(size_type=SizeType.ARBITRARY, typical=[1024, 2048, 4096])
    SECURITY_PROOF = SecurityProofType.DISCRETE_LOGARITHM

    @classproperty
    def INPUT_SIZE(cls):
        return cls.KEY_SIZE

    @classproperty
    def OUTPUT_SIZE(cls):
        return cls.KEY_SIZE

    @classproperty
    def BLOCK_SIZE(cls):
        return cls.OUTPUT_SIZE


class SignatureAlg(NumberTheoreticalAlg):
    PRIMITIVE_TYPE = PrimitiveType.SIGNING
    KEY_SIZE       = SizeSpec(size_type=SizeType.ARBITRARY, typical=[160, 224, 256])
    OUTPUT_SIZE    = SizeSpec(size_type=SizeType.ARBITRARY, typical=[320, 448, 512])
    CIPHER_TYPE    = CipherType.NONE
    EPHEMERAL      = EphemeralSpec(ephemeral_type=EphemeralType.KEY, size=SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda signer: signer.KEY_SIZE))


class KeyExchangeAlg(Primitive):
    PRIMITIVE_TYPE = PrimitiveType.KEY_EXCHANGE
    SYMMETRY_TYPE  = SymmetryType.ASYMMETRIC
    SECURITY_PROOF = SecurityProofType.DISCRETE_LOGARITHM
    KEY_SIZE       = SizeSpec(size_type=SizeType.ARBITRARY, typical=[1024, 2048, 4096])

    @classproperty
    def INPUT_SIZE(cls):
        return cls.KEY_SIZE

    @classproperty
    def OUTPUT_SIZE(cls):
        return cls.KEY_SIZE

    @classproperty
    def BLOCK_SIZE(cls):
        return cls.KEY_SIZE


class StreamCipher(EncryptionAlg):
    SYMMETRY_TYPE    = SymmetryType.SYMMETRIC
    CIPHER_TYPE      = CipherType.STREAM_CIPHER
    KEY_SIZE         = SizeSpec(size_type=SizeType.RANGE, sizes=[128, 256])
    INPUT_SIZE       = SizeSpec(size_type=SizeType.ARBITRARY)
    OUTPUT_SIZE      = SizeSpec(size_type=SizeType.ARBITRARY)
    BLOCK_SIZE       = SizeSpec(size_type=SizeType.SINGLE, sizes=8)
    IO_RELATION_TYPE = IORelationType.EQUAL

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
    IO_RELATION_TYPE   = IORelationType.EQUAL

    @classproperty
    def INPUT_SIZE(cls):
        return cls.BLOCK_SIZE

    @classproperty
    def OUTPUT_SIZE(cls):
        return cls.BLOCK_SIZE


_bcm_attr_set = {'underlying_mode', 'cipher', 'H', 'sector_encryptor', 'nonce', 'iv', 'counter', 'byteorder'}
class BlockCipherMode(EncryptionAlg):
    SYMMETRY_TYPE    = SymmetryType.SYMMETRIC
    KEY_SIZE         = SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda mode: mode.cipher.KEY_SIZE)
    INPUT_SIZE       = SizeSpec(size_type=SizeType.ARBITRARY)
    OUTPUT_SIZE      = SizeSpec(size_type=SizeType.ARBITRARY)
    BLOCK_SIZE       = SizeSpec(size_type=SizeType.DEPENDENT, selector=lambda mode: mode.cipher.BLOCK_SIZE)
    IO_RELATION_TYPE = IORelationType.EQUAL


    def __reprdir__(self):
        return [k for k in self.__dict__ if k in _bcm_attr_set]

    def check_ciphertext_length(self, ciphertext: bytes):
        if not len(ciphertext) or len(ciphertext) % self.cipher.block_size != 0:
            raise CiphertextLengthException("Ciphertext is not a multiple of the block size")


class StreamingBlockCipherMode(BlockCipherMode):
    CIPHER_TYPE = CipherType.STREAM_CIPHER
    BLOCK_SIZE  = SizeSpec(size_type=SizeType.SINGLE, sizes=8)


class AuthenticatedCipher(EncryptionAlg):
    def verify_tag(self, tag: bytes, given_tag: bytes):
        from samson.utilities.runtime import RUNTIME

        if not RUNTIME.compare_bytes(tag, given_tag):
            raise InvalidMACException('Tag mismatch: authentication failed!')
