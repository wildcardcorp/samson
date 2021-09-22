from typing import List

from pyasn1.type.char import UTF8String
from samson.core.base_object import BaseObject
from pyasn1_modules import rfc2459, rfc5280
from pyasn1.codec.der import encoder, decoder
from pyasn1.type.univ import ObjectIdentifier

class RDN(BaseObject):
    OID        = None
    SHORT_NAME = None

    def __init__(self, value: bytes) -> None:
        self.value = value
    

    def _build(self, value_obj, should_encode: bool=True):
        if should_encode:
            value_obj = encoder.encode(value_obj)

        attr = rfc2459.AttributeTypeAndValue()
        attr['type']  = self.OID
        attr['value'] = value_obj

        rdn = rfc2459.RelativeDistinguishedName()
        rdn.setComponentByPosition(0, attr)
        return rdn


    def build(self) -> rfc2459.RelativeDistinguishedName:
        return self._build(self.type(self.value), should_encode=False)


    @staticmethod
    def parse(name: rfc2459.RelativeDistinguishedName) -> 'RDN':
        rdn   = name[0]
        oid   = rdn['type']
        value = bytes(rdn['value'])

        for subclass in RDN.__subclasses__():
            if subclass.OID == oid:
                return subclass.parse(value)

        parsed = RDN(value)
        parsed.OID  = oid
        parsed.SHORT_NAME = oid
        parsed.type = type(rdn['value'])
        return parsed


    @staticmethod
    def from_kv(k: str, v: str) -> 'RDN':
        for subclass in RDN.__subclasses__():
            if subclass.SHORT_NAME and subclass.SHORT_NAME.lower() == k.lower():
                return subclass(v.encode('utf-8'))


class SimpleRDN(RDN):
    TYPE = None

    def build(self) -> rfc2459.RelativeDistinguishedName:
        return self._build(self.TYPE(self.value))


    @classmethod
    def parse(cls, value: bytes) -> 'SimpleRDN':
        if cls.TYPE:
            spec = cls.TYPE()
        else:
            spec = None

        real_val, _  = decoder.decode(value, asn1Spec=spec)
        return cls(bytes(real_val))


class ChoiceRDN(RDN):
    DEFAULT_TYPE = UTF8String

    def __init__(self, value: bytes, subtype=None) -> None:
        if not subtype:
            subtype = self.DEFAULT_TYPE
        
        self.subtype = subtype
        super().__init__(value)

    def build(self) -> rfc2459.RelativeDistinguishedName:
        return self._build(self.subtype(self.value))


    @classmethod
    def parse(cls, value: bytes) -> 'SimpleRDN':
        real_val, _  = decoder.decode(value)
        return cls(bytes(real_val), type(real_val))



class CommonName(ChoiceRDN, RDN):
    OID  = ObjectIdentifier([2, 5, 4, 3])
    TYPE = rfc2459.X520CommonName
    SHORT_NAME = "CN"


class OrganizationName(ChoiceRDN, RDN):
    OID  = ObjectIdentifier([2, 5, 4, 10])
    TYPE = rfc2459.X520OrganizationName
    SHORT_NAME = "O"


class CountryName(ChoiceRDN, RDN):
    OID  = ObjectIdentifier([2, 5, 4, 6])
    TYPE = rfc2459.CountryName
    SHORT_NAME = "C"


class LocalityName(ChoiceRDN, RDN):
    OID  = ObjectIdentifier([2, 5, 4, 7])
    TYPE = rfc2459.X520LocalityName
    SHORT_NAME = "L"


class StateName(ChoiceRDN, RDN):
    OID  = ObjectIdentifier([2, 5, 4, 8])
    TYPE = rfc5280.X520StateOrProvinceName
    SHORT_NAME = "ST"


class EmailAddress(SimpleRDN, RDN):
    OID  = ObjectIdentifier('1.2.840.113549.1.9.1')
    TYPE = rfc5280.EmailAddress
    SHORT_NAME = "emailAddress"


class OrganizationalUnit(ChoiceRDN, RDN):
    OID = ObjectIdentifier([2, 5, 4, 11])
    TYPE = rfc2459.X520OrganizationalUnitName
    SHORT_NAME = 'OU'


class SerialNumber(ChoiceRDN, RDN):
    OID  = ObjectIdentifier([2, 5, 4, 5])
    SHORT_NAME = "serialNumber"


class StreetAddress(ChoiceRDN, RDN):
    OID  = ObjectIdentifier([2, 5, 4, 9])
    SHORT_NAME = "streetAddress"


class BusinessCategory(ChoiceRDN, RDN):
    OID  = ObjectIdentifier([2, 5, 4, 15])
    SHORT_NAME = "businessCategory"


class JurisdictionCountryName(ChoiceRDN, RDN):
    OID  = ObjectIdentifier('1.3.6.1.4.1.311.60.2.1.3')
    SHORT_NAME = "jurisdictionC"


class DomainComponent(SimpleRDN, RDN):
    OID  = ObjectIdentifier('0.9.2342.19200300.100.1.25')
    TYPE = rfc5280.DomainComponent
    SHORT_NAME = "DC"


class RDNSequence(BaseObject):
    def __init__(self, rdns: List[RDN]) -> None:
        self.rdns = rdns
    

    def __reprdir__(self):
        return ['__raw__']
    

    def __str__(self):
        return self.__raw__


    @property
    def __raw__(self):
        return ','.join([f'{rdn.SHORT_NAME}={rdn.value.decode()}' for rdn in self.rdns])


    @staticmethod
    def parse(rdn_seq: rfc2459.RDNSequence) -> 'RDNSequence':
        return RDNSequence([RDN.parse(rdn) for rdn in rdn_seq])
    

    def build(self):
        rdn_seq = rfc2459.RDNSequence()
        for rdn in self.rdns:
            rdn_seq.append(rdn.build())
        
        return rdn_seq


    @staticmethod
    def parse_string(rdn_str: str) -> 'RDNSequence':
        rdn_parts = rdn_str.split('=')

        # Here we're careful of commas in RDNs
        # We also use 'key_idx' to keep track of the position
        # of the RDNs
        rdn_dict = []
        key      = rdn_parts[0]
        next_key = key

        for part in rdn_parts[1:-1]:
            parts = part.split(',')
            curr_val, next_key = ','.join(parts[:-1]), parts[-1]

            rdn_dict.append((key, curr_val))
            key           = next_key

        rdn_dict.append((next_key, rdn_parts[-1]))

        seq = []
        for k,v in rdn_dict:
            seq.append(RDN.from_kv(k, v))

        return RDNSequence(seq)


    @staticmethod
    def wrap(rdn_seq):
        if type(rdn_seq) is str:
            rdn_seq = RDNSequence.parse_string(rdn_seq)
        
        return rdn_seq
