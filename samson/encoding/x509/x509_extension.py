from datetime import datetime, timezone
from pyasn1.error import PyAsn1Error
from pyasn1.type.char import IA5String, GeneralString
from samson.utilities.bytes import Bytes
from typing import List, Union
from pyasn1_modules import rfc2459, rfc5280, rfc3280
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import BitString, Integer, Null, ObjectIdentifier, OctetString, Boolean, SequenceOf, Sequence
from pyasn1.type import namedtype, constraint
from pyasn1.type.useful import UTCTime
from pyasn1.type import tag
from enum import Enum, IntFlag
from samson.core.base_object import BaseObject
from samson.encoding.tls.tls_crypto import TLSSCTList
from samson.encoding.x509.x509_rdn import RDNSequence
from samson.encoding.x509.oids import *

MAX = float('inf')


class GeneralName(BaseObject):
    TAG = None

    def __init__(self, name: str) -> None:
        self.name = name


    @classmethod
    def parse_recursive(cls, name: rfc2459.GeneralName):
        n_type = name.getName()

        if n_type == cls.TAG:
            return cls.parse(name)

        for subclass in cls.__subclasses__():
            name_obj = subclass.parse_recursive(name)

            if name_obj:
                return name_obj
    


class RDNName(GeneralName):

    @classmethod
    def parse(cls, name: rfc2459.GeneralName) -> 'RDNName':
        n_type = name.getName()
        value  = name[n_type]

        for key in ['rdnSequence', '']:
            if key in value:
                break

        return cls(RDNSequence.parse(value[key]))


    def build(self) -> rfc5280.GeneralName:
        n_value = self.name.build()
        name = rfc5280.GeneralName()

        com  = name.componentType[self.TAG]
        com_name = com.getName()

        sub_name = name[self.TAG].clone()
        sub_name['rdnSequence'] = n_value
        name[com_name] = sub_name

        return name



class StringName(GeneralName):

    @classmethod
    def parse(cls, name: rfc2459.GeneralName) -> 'StringName':
        n_type = name.getName()
        value  = name[n_type]
        return cls(str(value))


    def build(self) -> rfc5280.GeneralName:
        name = rfc5280.GeneralName()

        com  = name.componentType[self.TAG]
        com_type = com.getType()
        com_name = com.getName()

        name[com_name] = com_type.clone(self.name)

        return name



class OctetName(GeneralName):

    @classmethod
    def parse(cls, name: rfc2459.GeneralName) -> 'OctetName':
        n_type = name.getName()
        value  = name[n_type]
        value = '.'.join([str(part) for part in bytes(value)])
        return cls(value)


    def build(self) -> rfc5280.GeneralName:
        name = rfc5280.GeneralName()

        com  = name.componentType[self.TAG]
        com_type = com.getType()
        com_name = com.getName()

        n_value = [int(part) for part in self.name.split('.')]
        n_value = bytes(n_value)
        name[com_name] = com_type.clone(n_value)

        return name



# https://datatracker.ietf.org/doc/html/rfc4120
# https://datatracker.ietf.org/doc/html/rfc4556#appendix-A
class KRB5Names(SequenceOf):
    pass

KRB5Names.componentType = GeneralString()


class PrincipalName(Sequence):
    pass


PrincipalName.componentType = namedtype.NamedTypes(
    namedtype.NamedType('name-type', Integer().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
    namedtype.NamedType('name-string', KRB5Names().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
)

class KRB5PrincipalName(Sequence):
    pass


KRB5PrincipalName.componentType = namedtype.NamedTypes(
    namedtype.NamedType('realm', GeneralString().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
    namedtype.NamedType('principalName', PrincipalName().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
)


class OtherName(GeneralName):
    TAG = 'otherName'

    def __init__(self, oid: str, data: bytes) -> None:
        self.oid  = oid
        self.data = data


    def _build(self, value: object, oid: str=None) -> rfc5280.GeneralName:
        gen_name = rfc5280.GeneralName()

        if hasattr(self, 'oid') and not oid:
            oid = self.oid
        
        if type(value) is not bytes:
            value = encoder.encode(value)

        if oid:
            if type(oid) is OtherNameOID:
                oid = oid.value

        name = gen_name['otherName']
        name['type-id'] = ObjectIdentifier(oid or self.NAME_OID.value)
        name['value']   = name['value'].clone(value)
        return gen_name


    def build(self) -> rfc5280.GeneralName:
        return self._build(self.data)


    @staticmethod
    def parse(other_name: rfc5280.GeneralName) -> 'OtherName':
        other_name = other_name['otherName']
        name_oid   = str(other_name['type-id'])

        try:
            name_oid = OtherNameOID(name_oid)
        except ValueError:
            pass

        value = bytes(other_name['value'])

        for subclass in OtherName.__subclasses__():
            if subclass.NAME_OID == name_oid:
                return subclass.parse(value)

        return OtherName(name_oid, value)



class UserPrincipalName(OtherName):
    NAME_OID   = OtherNameOID.USER_PRINCIPAL_NAME
    SHORT_NAME = "upn"

    def __init__(self, upn: bytes) -> None:
        self.upn = upn


    def build(self) -> bytes:
        return super()._build(rfc2459.UTF8String(self.upn))


    @staticmethod
    def parse(data: bytes) -> 'UserPrincipalName':
        upn, _ = decoder.decode(data)
        return UserPrincipalName(str(upn))



class KerberosPrincipalName(OtherName):
    NAME_OID   = OtherNameOID.KERBEROS_PRINCIPAL_NAME
    SHORT_NAME = "kpn"

    def __init__(self, realm: str, name_type: int, name_str: str) -> None:
        self.realm     = realm
        self.name_type = name_type
        self.name_str  = name_str


    def build(self) -> bytes:
        kpn = KRB5PrincipalName()
        kpn['realm'] = kpn['realm'].clone(self.realm)

        pn = kpn['principalName'].clone()
        pn['name-type'] = pn['name-type'].clone(self.name_type)

        name_str = pn['name-string'].clone()
        for s in self.name_str.split('/'):
            name_str.append(s)
        
        pn['name-string'] = name_str
        kpn['principalName'] = pn

        return super()._build(kpn)


    @staticmethod
    def parse(data: bytes) -> 'KerberosPrincipalName':
        kpn, _ = decoder.decode(data, asn1Spec=KRB5PrincipalName())
        realm  = str(kpn['realm'])

        name_type = int(kpn['principalName']['name-type'])
        name_str  = '/'.join([str(s) for s in kpn['principalName']['name-string']])

        return KerberosPrincipalName(realm=realm, name_type=name_type, name_str=name_str)



class DirectoryName(RDNName):
    SHORT_NAME = 'dir'
    TAG        = 'directoryName'

class DNSName(StringName):
    SHORT_NAME = 'dns'
    TAG        = 'dNSName'

class URIName(StringName):
    SHORT_NAME = 'uri'
    TAG        = 'uniformResourceIdentifier'

class EmailName(StringName):
    SHORT_NAME = 'email'
    TAG        = 'rfc822Name'

class IPAddressName(OctetName):
    SHORT_NAME = 'ip'
    TAG        = 'iPAddress'



def merge_enums(name: str, sub_enums: list):
    """
    References:
        https://stackoverflow.com/questions/33679930/how-to-extend-python-enum
    """
    import itertools
    merged = [[(prefix + kv.name, kv.value) for kv in enum] for prefix, enum in itertools.chain(sub_enums)]
    merged = [item for sublist in merged for item in sublist]
    return Enum(name, merged)


class X509IntFlag(IntFlag):
    def build(self):
        binary = bin(int(self))[2:].strip('0').zfill(self.get_size())
        return self.get_asn1_obj()(binary)
    

    @classmethod
    def get_size(cls):
        return len(cls)
    

    @staticmethod
    def get_asn1_obj():
        return None


    @classmethod
    def parse(cls, val_obj):
        val = int(val_obj)
        val = int(bin(val)[2:][::-1].zfill(cls.get_size())[::-1], 2)

        val = cls(val)
        size = len(val_obj.asBinary())
        val.get_size = lambda: size
        return val



class X509KeyUsageFlag(X509IntFlag):
    DIGITAL_SIGNATURE = 2**8
    NON_REPUDIATION   = 2**7
    KEY_ENCIPHERMENT  = 2**6
    DATA_ENCIPHERMENT = 2**5
    KEY_AGREEMENT     = 2**4
    KEY_CERT_SIGN     = 2**3
    CRL_SIGN          = 2**2
    ENCIPHER_ONLY     = 2**1
    DECIPHER_ONLY     = 2**0

    @staticmethod
    def get_asn1_obj():
        return rfc5280.KeyUsage



class X509Extension(BaseObject):
    EXT_TYPE = None

    def __init__(self, critical: bool=None) -> None:
        self.critical = critical


    def _build(self, value: object):
        ext = rfc2459.Extension()
        ext['extnID']    = ObjectIdentifier(self.EXT_TYPE.value)
        ext['critical']  = Boolean(self.critical)
        ext['extnValue'] = OctetString(encoder.encode(value))

        return ext


    def build(self) -> rfc5280.Extension:
        """
        For arbitrary extensions.
        """
        oid = self.oid
        if hasattr(oid, 'value'):
            oid = self.oid.value

        ext = rfc2459.Extension()
        ext['extnID']    = ObjectIdentifier(oid)
        ext['critical']  = Boolean(self.critical)
        ext['extnValue'] = OctetString(self.data)

        return ext


    @staticmethod
    def parse(extension: rfc5280.Extension) -> 'X509Extension':
        ext_type = str(extension['extnID'])
        critical = bool(extension['critical'])

        try:
            ext_type = OID(ext_type)

            for subclass in X509Extension.__subclasses__():
                if subclass.EXT_TYPE == ext_type:
                    return subclass.parse(bytes(extension['extnValue']), critical)
        except ValueError:
            pass

        ext = X509Extension(critical=critical)
        ext.oid = ext_type
        ext.data = bytes(extension['extnValue'])
        return ext



class _AlternateName(object):
    EXT_TYPE = None

    def __init__(self, names: List[GeneralName], critical: bool=False, allow_empty: bool=True) -> None:
        self.names = names
        self.allow_empty = allow_empty
        super().__init__(critical=critical)
    

    def build(self) -> rfc5280.Extension:
        san = self.NAME_SPEC()

        for name in self.names:
            san.append(name.build())

        if not san.isValue:
            if self.allow_empty:
                san = SequenceOf()
                san.extend([])
            else:
                raise ValueError('Name sequence cannot be empty')

        return super()._build(san)


    @classmethod
    def parse(cls, value_bytes: bytes, critical: bool) -> '_AlternateName':
        san, _ = decoder.decode(value_bytes, asn1Spec=cls.NAME_SPEC())
        sans   = []
        for name in san:
            sans.append(GeneralName.parse_recursive(name))

        return cls(names=sans, critical=critical)


class X509SubjectAlternativeName(_AlternateName, X509Extension):
    EXT_TYPE  = OID.SUBJECT_ALTERNATIVE_NAME
    NAME_SPEC = rfc2459.SubjectAltName


class X509IssuerAlternativeName(_AlternateName, X509Extension):
    EXT_TYPE  = OID.ISSUER_ALTERNATIVE_NAME
    NAME_SPEC = rfc2459.IssuerAltName



# This is wrong, but some certs use this!
class BasicConstraintsExplicit(Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('cA', Boolean()),
        namedtype.OptionalNamedType('pathLenConstraint',
                                    Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(0, MAX)))
    )


class X509BasicConstraints(X509Extension):
    EXT_TYPE = OID.BASIC_CONSTRAINTS
    BC_TYPE  = rfc2459.BasicConstraints

    def __init__(self, is_ca: bool=True, path_len: int=None, critical: bool=True) -> None:
        self.is_ca    = is_ca
        self.path_len = path_len
        super().__init__(critical=critical)
    
    
    def __reprdir__(self):
        return ['is_ca', 'path_len']
    

    def build(self) -> rfc5280.Extension:
        ca_value = self.BC_TYPE()
        ca_value['cA'] = self.is_ca

        if self.path_len is not None:
            ca_value['pathLenConstraint'] = self.path_len

        return super()._build(ca_value)


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509BasicConstraints':
        try:
            ext_val, _ = decoder.decode(value_bytes, asn1Spec=BasicConstraintsExplicit())
            bc_type    = BasicConstraintsExplicit
        except PyAsn1Error:
            ext_val, _ = decoder.decode(value_bytes, asn1Spec=rfc2459.BasicConstraints())
            bc_type    = rfc2459.BasicConstraints


        path_len = ext_val['pathLenConstraint']

        if path_len.isValue:
            path_len = int(path_len)
        else:
            path_len = None

        parsed = X509BasicConstraints(is_ca=bool(ext_val['cA']), path_len=path_len, critical=critical)
        parsed.BC_TYPE = bc_type
        return parsed



class X509KeyUsage(X509Extension):
    EXT_TYPE = OID.KEY_USAGE

    def __init__(self, key_usage: X509KeyUsageFlag, critical: bool=True) -> None:
        self.key_usage = key_usage
        super().__init__(critical=critical)
    

    def build(self) -> rfc5280.Extension:
        return super()._build(self.key_usage.build())


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509KeyUsage':
        ext_val, _ = decoder.decode(value_bytes, asn1Spec=rfc5280.KeyUsage())

        return X509KeyUsage(key_usage=X509KeyUsageFlag.parse(ext_val), critical=critical)



class X509ExtendedKeyUsage(X509Extension):
    EXT_TYPE = OID.EXTENDED_KEY_USAGE

    def __init__(self, oids: List[X509ExtKeyUsageType], critical: bool=False) -> None:
        self.oids = oids
        super().__init__(critical=critical)
    

    def build(self) -> rfc5280.Extension:
        ext_ku = rfc5280.ExtKeyUsageSyntax()

        for oid in self.oids:
            if hasattr(oid, 'value'):
                oid = oid.value

            key_purpose = rfc5280.KeyPurposeId(oid)
            ext_ku.append(key_purpose)
        
        return super()._build(ext_ku)


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509ExtendedKeyUsage':
        ext_val, _ = decoder.decode(value_bytes, asn1Spec=rfc5280.ExtKeyUsageSyntax())

        oids = []
        for key_purpose in ext_val:
            oid = str(key_purpose)
            try:
                oid = OID(oid)
            except ValueError:
                pass

            oids.append(oid)
        
        return X509ExtendedKeyUsage(oids=oids, critical=critical)



class X509SubjectKeyIdentifier(X509Extension):
    EXT_TYPE = OID.SUBJECT_KEY_IDENTIFER

    def __init__(self, key_identifier: bytes=None, critical: bool=False) -> None:
        self.key_identifier = key_identifier
        super().__init__(critical=critical)
    

    def build(self) -> rfc5280.Extension:
        ski = rfc2459.SubjectKeyIdentifier(self.key_identifier)
        return super()._build(ski)


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509SubjectKeyIdentifier':
        ext_val, _ = decoder.decode(value_bytes, asn1Spec=rfc2459.SubjectKeyIdentifier())
        return X509SubjectKeyIdentifier(key_identifier=bytes(ext_val), critical=critical)



# https://datatracker.ietf.org/doc/html/rfc3280#section-5.2.5
class X509ReasonCodeFlag(X509IntFlag):
    UNSPECIFIED            = 2**10
    KEY_COMPROMISE         = 2**9
    CA_COMPROMISE          = 2**8
    AFFILIATION_CHANGED    = 2**7
    SUPERSEDED             = 2**6
    CESSATION_OF_OPERATION = 2**5
    CERTIFICATE_HOLD       = 2**4
    REMOVE_FROM_CRL        = 2**2
    PRIVILEGE_WITHDRAWN    = 2**1
    AA_COMPROMISE          = 2**0

    @staticmethod
    def get_size():
        return 11

    @staticmethod
    def get_asn1_obj():
        return rfc3280.ReasonFlags


class X509CRLReason(Enum):
    UNSPECIFIED            = 0
    KEY_COMPROMISE         = 1
    CA_COMPROMISE          = 2
    AFFILIATION_CHANGED    = 3
    SUPERSEDED             = 4
    CESSATION_OF_OPERATION = 5
    CERTIFICATE_HOLD       = 6
    REMOVE_FROM_CRL        = 8
    PRIVILEGE_WITHDRAWN    = 9
    AA_COMPROMISE          = 10


class X509ReasonCode(X509Extension):
    EXT_TYPE  = OID.REASON_CODE

    def __init__(self, reason_code: X509CRLReason, critical: bool=False) -> None:
        self.reason_code = reason_code
        super().__init__(critical=critical)


    def build(self) -> rfc5280.Extension:
        return super()._build(Integer(self.reason_code.value))


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509ReasonCode':
        ext_val, _  = decoder.decode(value_bytes)
        return X509ReasonCode(reason_code=X509CRLReason(ext_val), critical= critical)



class X509CRLDistributionPoint(BaseObject):
    def __init__(self, names: List[GeneralName]=None, reasons: X509ReasonCodeFlag=None, crl_issuer: List[GeneralName]=None) -> None:
        self.names      = names
        self.reasons    = reasons
        self.crl_issuer = crl_issuer


    def build(self) -> rfc5280.DistributionPoint:
        points = rfc5280.CRLDistributionPoints()
        point  = points[0].clone()

        if self.names:
            point_name = point['distributionPoint'].clone()

            gen_names = point_name['fullName'].clone()

            for name in self.names:
                gen_names.append(name.build())

            point_name['fullName'] = gen_names
            point['distributionPoint'] = point_name


        if self.reasons is not None:
            point['reasons'] = self.reasons.build()


        if self.crl_issuer:
            gen_names = point['cRLIssuer'].clone()

            for name in self.crl_issuer:
                gen_names.append(name.build())

            point['cRLIssuer'] = gen_names

        return point
    

    @staticmethod
    def parse(crl_dist_point: rfc5280.DistributionPoint) -> 'X509CRLDistributionPoint':
        point_name = None
        if crl_dist_point['distributionPoint'].isValue:
            point_name = [GeneralName.parse_recursive(name) for name in crl_dist_point['distributionPoint']['fullName']]


        reasons = None
        if crl_dist_point['reasons'].isValue:
            reasons = X509ReasonCodeFlag.parse(crl_dist_point['reasons'])


        crl_issuer = None
        if crl_dist_point['cRLIssuer'].isValue:
            crl_issuer = [GeneralName.parse_recursive(name) for name in crl_dist_point['cRLIssuer']]
        

        return X509CRLDistributionPoint(names=point_name, reasons=reasons, crl_issuer=crl_issuer)



class X509IssuingDistributionPoint(X509Extension):
    EXT_TYPE  = OID.ISSUING_DISTRIBUTION_POINT

    def __init__(
            self,
            distribution_point: List[GeneralName],
            only_contains_user_certs: bool=False,
            only_contains_ca_certs: bool=False,
            only_some_reasons: X509ReasonCodeFlag=None,
            indirect_crl: bool=False,
            only_contains_attr_certs: bool=False, 
            critical: bool=False
        ) -> None:

        self.distribution_point = distribution_point
        self.only_contains_user_certs = only_contains_user_certs
        self.only_contains_ca_certs = only_contains_ca_certs
        self.only_some_reasons = only_some_reasons
        self.indirect_crl = indirect_crl
        self.only_contains_attr_certs = only_contains_attr_certs
        super().__init__(critical=critical)


    def build(self) -> rfc5280.Extension:
        idp = rfc3280.IssuingDistributionPoint()

        if self.distribution_point:
            gen_names = idp['distributionPoint']['fullName'].clone()

            for name in self.distribution_point:
                gen_names.append(name.build())
            
            idp['distributionPoint']['fullName'] = gen_names

        idp['onlyContainsUserCerts'] = self.only_contains_user_certs
        idp['onlyContainsCACerts'] = self.only_contains_ca_certs
        idp['indirectCRL'] = self.indirect_crl
        idp['onlyContainsAttributeCerts'] = self.only_contains_attr_certs

        if self.only_some_reasons is not None:
            idp['onlySomeReasons'] = rfc3280.ReasonFlags(self.only_some_reasons.build())

        return super()._build(idp)


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509IssuingDistributionPoint':
        ext_val, _  = decoder.decode(value_bytes, asn1Spec=rfc3280.IssuingDistributionPoint())
        dp_name = ext_val['distributionPoint']
        names   = [GeneralName.parse_recursive(name) for name in dp_name['fullName']]

        only_contains_user_certs = bool(ext_val['onlyContainsUserCerts'])
        only_contains_ca_certs   = bool(ext_val['onlyContainsCACerts'])
        indirect_crl             = bool(ext_val['indirectCRL'])
        only_contains_attr_certs = bool(ext_val['onlyContainsAttributeCerts'])

        only_some_reasons = None
        if ext_val['onlySomeReasons'].isValue:
            only_some_reasons = X509ReasonCodeFlag.parse(ext_val['onlySomeReasons'])


        return X509IssuingDistributionPoint(
            distribution_point=names,
            only_contains_user_certs=only_contains_user_certs,
            only_contains_ca_certs=only_contains_ca_certs,
            only_some_reasons=only_some_reasons,
            indirect_crl=indirect_crl,
            only_contains_attr_certs=only_contains_attr_certs,
            critical= critical
        )


class X509CRLDistributionPoints(X509Extension):
    EXT_TYPE = OID.CRL_DISTRIBUTION_POINTS

    def __init__(self, distribution_points: List[X509CRLDistributionPoint], critical: bool=False) -> None:
        self.distribution_points = distribution_points
        super().__init__(critical=critical)
    

    def build(self) -> rfc5280.Extension:
        points = rfc5280.CRLDistributionPoints()

        for distribution_point in self.distribution_points:
            points.append(distribution_point.build())
        
        return super()._build(points)


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509CRLDistributionPoints':
        ext_val, _ = decoder.decode(value_bytes, asn1Spec=rfc5280.CRLDistributionPoints())
        return X509CRLDistributionPoints(distribution_points=[X509CRLDistributionPoint.parse(point) for point in ext_val], critical=critical)



class X509AuthorityKeyIdentifier(X509Extension):
    EXT_TYPE = OID.AUTHORITY_KEY_IDENTIFIER

    def __init__(self, key_identifier: bytes, authority_cert_issuer: List[str]=None, authority_cert_serial_number: int=None, critical: bool=False) -> None:
        self.key_identifier = key_identifier
        self.authority_cert_issuer = authority_cert_issuer
        self.authority_cert_serial_number = authority_cert_serial_number
        super().__init__(critical=critical)
    

    def build(self) -> rfc5280.Extension:
        aki = rfc5280.AuthorityKeyIdentifier()

        if self.key_identifier is not None:
            aki['keyIdentifier'] = aki['keyIdentifier'].clone(self.key_identifier)

        if self.authority_cert_issuer is not None:
            gen_names = aki['authorityCertIssuer'].clone()

            for name in self.authority_cert_issuer:
                gen_names.append(name.build())

            aki['authorityCertIssuer'] = gen_names

        if self.authority_cert_serial_number is not None:
            aki['authorityCertSerialNumber'] = aki['authorityCertSerialNumber'].clone(self.authority_cert_serial_number)

        return super()._build(aki)


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509AuthorityKeyIdentifier':
        ext_val, _ = decoder.decode(value_bytes, asn1Spec=rfc5280.AuthorityKeyIdentifier())

        key_identifier = bytes(ext_val['keyIdentifier']) if ext_val['keyIdentifier'].isValue else None
        authority_cert_issuer = [GeneralName.parse_recursive(name) for name in ext_val['authorityCertIssuer']]
        authority_cert_serial_number = int(ext_val['authorityCertSerialNumber']) if ext_val['authorityCertSerialNumber'].isValue else None

        return X509AuthorityKeyIdentifier(key_identifier=key_identifier, authority_cert_issuer=authority_cert_issuer, authority_cert_serial_number=authority_cert_serial_number, critical=critical)



class X509AccessDescription(BaseObject):
    def __init__(self, access_method: X509AccessDescriptorType, access_location: 'str') -> None:
        self.access_method   = access_method
        self.access_location = access_location


class X509AuthorityInfoAccess(X509Extension):
    EXT_TYPE = OID.AUTHORITY_INFO_ACCESS

    def __init__(self, access_descriptions: List[X509AccessDescription], critical: bool=False) -> None:
        self.access_descriptions = access_descriptions
        super().__init__(critical=critical)


    def build(self) -> rfc5280.Extension:
        aia   = rfc5280.AuthorityInfoAccessSyntax()

        for access_desc in self.access_descriptions:
            acc_desc = rfc5280.AccessDescription()
            acc_desc['accessMethod']   = ObjectIdentifier(access_desc.access_method.value)
            acc_desc['accessLocation'] = access_desc.access_location.build()
            aia.append(acc_desc)

        return super()._build(aia)


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509AuthorityInfoAccess':
        ext_val, _ = decoder.decode(value_bytes, asn1Spec=rfc5280.AuthorityInfoAccessSyntax())

        access_descriptions = []
        for access_desc in ext_val:
            access_method   = X509AccessDescriptorType(str(access_desc['accessMethod']))
            access_location = GeneralName.parse_recursive(access_desc['accessLocation'])
            access_descriptions.append(X509AccessDescription(access_method, access_location))

        return X509AuthorityInfoAccess(access_descriptions=access_descriptions, critical=critical)


class X509PolicyQualifier(BaseObject):
    def build(self) -> rfc5280.PolicyQualifierInfo:
        oid  = self.QUALIFIER_TYPE
        data = self.build_data()

        if type(oid) is X509CertificatePolicyQualifierType:
            oid = oid.value

        qualifier = rfc5280.PolicyQualifierInfo()
        qualifier['policyQualifierId'] = oid
        qualifier['qualifier'] = encoder.encode(data)
        return qualifier


    @classmethod
    def __parse(cls, qualifier: rfc5280.PolicyQualifierInfo) -> 'X509PolicyQualifier':
        data = decoder.decode(bytes(qualifier['qualifier']), asn1Spec=cls.DATA_SPEC())[0]
        return cls(*cls.parse_data(data))


    @staticmethod
    def parse(qualifier: rfc5280.PolicyQualifierInfo) -> 'X509PolicyQualifier':
        oid = str(qualifier['policyQualifierId'])
        oid = X509CertificatePolicyQualifierType(oid)

        for subclass in X509PolicyQualifier.__subclasses__():
            if subclass.QUALIFIER_TYPE == oid:
                return subclass.__parse(qualifier)
        
        raise ValueError("Unable to parse qualifier")



class X509CertificatePracticeStatement(X509PolicyQualifier):
    QUALIFIER_TYPE = X509CertificatePolicyQualifierType.CERTIFICATE_PRACTICE_STATEMENT
    DATA_SPEC      = IA5String

    def __init__(self, data: bytes) -> None:
        self.data = data


    def build_data(self) -> object:
        return IA5String(self.data)

    @staticmethod
    def parse_data(data: object) -> str:
        return (str(data),)



class DisplayText(BaseObject):

    def __init__(self, value: bytes, text_type: str='utf8String') -> None:
        self.value = value
        self.text_type = text_type

    def __repr__(self):
        return self.value.decode()

    def __str__(self):
        return repr(self)
    

    @staticmethod
    def wrap(data: Union[str, bytes, 'DisplayText']) -> 'DisplayText':
        if type(data) in [str, bytes]:
            if type(data) is str:
                data = data.encode()

            data = DisplayText(data)
        
        return data



    @staticmethod
    def parse(display: rfc5280.DisplayText) -> 'DisplayText':
        text_type = display.getName()
        value     = bytes(display[text_type])
        return DisplayText(value, text_type)


    def build(self) -> rfc5280.DisplayText:
        display = rfc5280.DisplayText()
        display[self.text_type] = self.value
        return display



class X509UserNotice(X509PolicyQualifier):
    QUALIFIER_TYPE = X509CertificatePolicyQualifierType.USER_NOTICE
    DATA_SPEC      = rfc5280.UserNotice

    def __init__(self, explicit_text: Union[bytes, str, DisplayText]=None, org_name: Union[bytes, str, DisplayText]=None, notice_nums: List[int]=None) -> None:
        if explicit_text is not None:
            explicit_text = DisplayText.wrap(explicit_text)

        if org_name is not None:
            org_name = DisplayText.wrap(org_name)

        self.explicit_text = explicit_text
        self.org_name      = org_name
        self.notice_nums   = notice_nums


    def build_data(self) -> object:
        data = rfc5280.UserNotice()

        if self.explicit_text is not None:
            data['explicitText'] = self.explicit_text.build()
        
        notice_ref = data['noticeRef']
        if self.org_name is not None:
            notice_ref['organization'] = self.org_name.build()
        
        if self.notice_nums is not None:
            notice_ref['noticeNumbers'].extend(self.notice_nums)

        return data


    @staticmethod
    def parse_data(data: object) -> str:
        ex_text = data['explicitText']

        if ex_text.isValue:
            ex_text = DisplayText.parse(ex_text)
        else:
            ex_text = None

        notice_ref = data['noticeRef']
        org_name   = notice_ref['organization']

        if org_name.isValue:
            org_name = DisplayText.parse(org_name)
        else:
            org_name = None

        if notice_ref['noticeNumbers'].isValue:
            notice_nums = [int(i) for i in notice_ref['noticeNumbers']]
        else:
            notice_nums = None

        return ex_text, org_name, notice_nums




class X509CertificatePolicy(BaseObject):
    def __init__(self, oid: str, qualifiers: List[X509PolicyQualifier]) -> None:
        self.oid = oid
        self.qualifiers = qualifiers


    def build(self) -> rfc5280.PolicyInformation:
        oid = self.oid

        if type(oid) is X509CertificatePolicyType:
            oid = oid.value

        poly_info = rfc5280.PolicyInformation()
        policy_id = rfc5280.CertPolicyId(oid)

        poly_info['policyIdentifier'] = policy_id

        if self.qualifiers:
            for qualifier in self.qualifiers:
                poly_info['policyQualifiers'].append(qualifier.build())

        return poly_info


    @staticmethod
    def parse(policy_info: rfc5280.PolicyInformation) -> 'X509CertificatePolicy':
        oid = str(policy_info['policyIdentifier'])

        try:
            oid = X509CertificatePolicyType(oid)
        except ValueError:
            pass

        qualifiers = []
        for qualifier in policy_info['policyQualifiers']:
            qualifiers.append(X509PolicyQualifier.parse(qualifier))

        return X509CertificatePolicy(oid=oid, qualifiers=qualifiers)



class X509CertificatePolicies(X509Extension):
    EXT_TYPE = OID.CERTIFICATE_POLICIES

    def __init__(self, policies: List[X509CertificatePolicy], critical: bool=False) -> None:
        self.policies = policies
        super().__init__(critical=critical)
    

    def build(self) -> rfc5280.Extension:
        cert_policy = rfc5280.CertificatePolicies()

        for policy in self.policies:
            cert_policy.append(policy.build())

        return super()._build(cert_policy)


    @classmethod
    def parse(cls, value_bytes: bytes, critical: bool) -> 'X509CertificatePolicies':
        ext_val, _ = decoder.decode(value_bytes, asn1Spec=rfc5280.CertificatePolicies())

        policies = []
        for policy_info in ext_val:
            policies.append(X509CertificatePolicy.parse(policy_info))

        return cls(policies=policies, critical=critical)


class X509MicrosoftApplicationCertPolicies(X509CertificatePolicies, X509Extension):
    EXT_TYPE = OID.MICROSOFT_szOID_APPLICATION_CERT_POLICIES


class X509CertificateTransparency(X509Extension):
    EXT_TYPE = OID.CERTIFICATE_TRANSPARENCY

    def __init__(self, scts: TLSSCTList, critical: bool=False) -> None:
        self.scts = scts
        super().__init__(critical=critical)
    

    def build(self) -> rfc5280.Extension:
        sct_packed = bytes(self.scts.pack())
        return super()._build(OctetString(sct_packed))


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509CertificateTransparency':
        ext_val, _ = decoder.decode(value_bytes)
        scts, _    = TLSSCTList.unpack(Bytes(bytes(ext_val)))
        return X509CertificateTransparency(scts=scts, critical=critical)



class X509CertificateTransparencyPoison(X509Extension):
    EXT_TYPE = OID.CT_PRECERTIFICATE_POISON

    def __init__(self, critical: bool=True) -> None:
        super().__init__(critical=critical)
    

    def build(self) -> rfc5280.Extension:
        return super()._build(Null)


    @staticmethod
    def parse(_value_bytes: bytes, critical: bool) -> 'X509CertificateTransparencyPoison':
        return X509CertificateTransparencyPoison(critical=critical)



class X509PrivateKeyUsagePeriod(X509Extension):
    EXT_TYPE = OID.PRIVATE_KEY_USAGE_PERIOD

    def __init__(self, not_before: datetime=None, not_after: datetime=None, critical: bool=False) -> None:
        self.not_before = not_before
        self.not_after  = not_after
        super().__init__(critical=critical)
    

    def build(self) -> rfc5280.Extension:
        pkup = rfc5280.PrivateKeyUsagePeriod()

        if self.not_before:
            pkup[0] = pkup[0].clone(UTCTime(self.not_before.strftime('%Y%m%d%H%M%SZ')))
        
        if self.not_after:
            pkup[1] = pkup[1].clone(UTCTime(self.not_after.strftime('%Y%m%d%H%M%SZ')))

        return super()._build(pkup)


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509PrivateKeyUsagePeriod':
        ext_val, _ = decoder.decode(value_bytes, asn1Spec=rfc5280.PrivateKeyUsagePeriod())
        not_before = ext_val[0].asDateTime.replace(tzinfo=timezone.utc) if ext_val[0].isValue else None
        not_after  = ext_val[1].asDateTime.replace(tzinfo=timezone.utc) if ext_val[1].isValue else None

        return X509PrivateKeyUsagePeriod(not_before=not_before, not_after=not_after, critical=critical)


class X509PolicyConstraints(X509Extension):
    EXT_TYPE = OID.POLICY_CONSTRAINTS

    def __init__(self, require_explicit_policy: int=None, inhibit_policy_mapping: int=None, critical: bool=True) -> None:
        self.require_explicit_policy = require_explicit_policy
        self.inhibit_policy_mapping  = inhibit_policy_mapping
        super().__init__(critical=critical)
    

    def build(self) -> rfc5280.Extension:
        pc = rfc5280.PolicyConstraints()

        if self.require_explicit_policy is not None:
            pc['requireExplicitPolicy'] = pc['requireExplicitPolicy'].clone(self.require_explicit_policy)
        

        if self.inhibit_policy_mapping is not None:
            pc['inhibitPolicyMapping'] = pc['inhibitPolicyMapping'].clone(self.inhibit_policy_mapping)

        return super()._build(pc)


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509PolicyConstraints':
        ext_val, _ = decoder.decode(value_bytes, asn1Spec=rfc5280.PolicyConstraints())

        require_explicit_policy = None
        if ext_val['requireExplicitPolicy'].isValue:
            require_explicit_policy = int(ext_val['requireExplicitPolicy'])


        inhibit_policy_mapping = None
        if ext_val['inhibitPolicyMapping'].isValue:
            inhibit_policy_mapping = int(ext_val['inhibitPolicyMapping'])


        return X509PolicyConstraints(require_explicit_policy=require_explicit_policy, inhibit_policy_mapping=inhibit_policy_mapping, critical=critical)



class _NetscapeStringExtension(object):
    def build(self) -> rfc5280.Extension:
        return super()._build(IA5String(getattr(self, self.DATA_ATTR)))


    @classmethod
    def parse(cls, value_bytes: bytes, critical: bool) -> '_NetscapeStringExtension':
        ext_val, _ = decoder.decode(value_bytes)
        return cls(**{cls.DATA_ATTR: str(ext_val), 'critical': critical})


class _NetscapeURLExtension(_NetscapeStringExtension):
    DATA_ATTR = 'url'

    def __init__(self, url: str, critical: bool=False) -> None:
        self.url = url
        super().__init__(critical=critical)


class X509NetscapeComment(_NetscapeStringExtension, X509Extension):
    EXT_TYPE  = OID.NETSCAPE_COMMENT
    DATA_ATTR = 'comment'

    def __init__(self, comment: str, critical: bool=False) -> None:
        self.comment = comment
        super().__init__(critical=critical)


class X509NetscapeBaseURL(_NetscapeURLExtension, X509Extension):
    EXT_TYPE  = OID.NETSCAPE_BASE_URL

class X509NetscapeRevocationURL(_NetscapeURLExtension, X509Extension):
    EXT_TYPE  = OID.NETSCAPE_REVOCATION_URL

class X509NetscapeCARevocationURL(_NetscapeURLExtension, X509Extension):
    EXT_TYPE  = OID.NETSCAPE_CA_REVOCATION_URL

class X509NetscapeRenewalURL(_NetscapeURLExtension, X509Extension):
    EXT_TYPE  = OID.NETSCAPE_RENEWAL_URL

class X509NetscapeCAPolicyURL(_NetscapeURLExtension, X509Extension):
    EXT_TYPE  = OID.NETSCAPE_CA_POLICY_URL

class X509NetscapeSSLServerName(_NetscapeURLExtension, X509Extension):
    EXT_TYPE  = OID.NETSCAPE_SSL_SERVER_NAME


class X509MicrosoftCSCAVersion(X509Extension):
    EXT_TYPE  = OID.MICROSOFT_CERTIFICATE_SERVICES_CA_VERSION

    def __init__(self, version: int, critical: bool=False) -> None:
        self.version = version
        super().__init__(critical=critical)
    

    def build(self) -> rfc5280.Extension:
        return super()._build(Integer(self.version))


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509MicrosoftCSCAVersion':
        ext_val, _ = decoder.decode(value_bytes)
        return X509MicrosoftCSCAVersion(version=int(ext_val), critical=critical)


class X509MicrosoftCSPreviousHash(X509Extension):
    EXT_TYPE  = OID.MICROSOFT_szOID_CERTSRV_PREVIOUS_CERT_HASH

    def __init__(self, hash: bytes, critical: bool=False) -> None:
        self.hash = hash
        super().__init__(critical=critical)
    

    def build(self) -> rfc5280.Extension:
        return super()._build(OctetString(self.hash))


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509MicrosoftCSPreviousHash':
        ext_val, _ = decoder.decode(value_bytes)
        return X509MicrosoftCSPreviousHash(hash=bytes(ext_val), critical=critical)




# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9da866e5-9ce9-4a83-9064-0d20af8b2ccf
class CertificateTemplateOID(Sequence):
    pass


CertificateTemplateOID.componentType = namedtype.NamedTypes(
    namedtype.NamedType('templateID', ObjectIdentifier()),
    namedtype.NamedType('templateMajorVersion', Integer()),
    namedtype.OptionalNamedType('templateMinorVersion', Integer())
)

class X509MicrosoftCertificateTemplate(X509Extension):
    EXT_TYPE  = OID.MICROSOFT_szOID_CERTIFICATE_TEMPLATE

    def __init__(self, template_id: str, major_version: int, minor_version: int, critical: bool=False) -> None:
        self.template_id   = template_id
        self.major_version = major_version
        self.minor_version = minor_version
        super().__init__(critical=critical)
    

    def build(self) -> rfc5280.Extension:
        cert_template = CertificateTemplateOID()
        cert_template['templateID'] = ObjectIdentifier(self.template_id)
        cert_template['templateMajorVersion'] = Integer(self.major_version)

        if cert_template['templateMinorVersion'] is not None:
            cert_template['templateMinorVersion'] = Integer(self.minor_version)
        return super()._build(cert_template)


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509MicrosoftCertificateTemplate':
        ext_val, _ = decoder.decode(value_bytes, asn1Spec=CertificateTemplateOID())
        template_id   = str(ext_val['templateID'] )
        major_version = int(ext_val['templateMajorVersion'])

        minor_version = None
        if ext_val['templateMinorVersion'].isValue:
            minor_version = int(ext_val['templateMinorVersion'])

        return X509MicrosoftCertificateTemplate(template_id=template_id, major_version=major_version, minor_version=minor_version, critical=critical)



class X509NetscapeCertTypeFlag(X509IntFlag):
    SSL_CLIENT        = 2**7
    SSL_SERVER        = 2**6
    SMIME             = 2**5
    OBJECT_SIGNING    = 2**4
    RESERVED          = 2**3
    SSL_CA            = 2**2
    SMIME_CA          = 2**1
    OBJECT_SIGNING_CA = 2**0

    @staticmethod
    def get_asn1_obj():
        return BitString


class X509NetscapeCertificateType(X509Extension):
    EXT_TYPE = OID.NETSCAPE_CERTIFICATE_TYPE

    def __init__(self, cert_type: X509NetscapeCertTypeFlag, critical: bool=False) -> None:
        self.cert_type = cert_type
        super().__init__(critical=critical)
    

    def build(self) -> rfc5280.Extension:
        return super()._build(self.cert_type.build())


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509NetscapeCertificateType':
        ext_val, _ = decoder.decode(value_bytes)

        return X509NetscapeCertificateType(cert_type=X509NetscapeCertTypeFlag.parse(ext_val), critical=critical)


# I honestly cannot find the last two bits
class X509EntrustInfoFlag(X509IntFlag):
    KEY_UPDATE_ALLOWED  = 2**7
    NEW_EXTENSIONS      = 2**6
    PKIX_CERTIFICATE    = 2**5
    ENTERPRISE_CATEGORY = 2**4
    WEB_CATEGORY        = 2**3
    SET_CATEGORY        = 2**2

    @staticmethod
    def get_size():
        return 8

    @staticmethod
    def get_asn1_obj():
        return BitString


# https://github.com/wireshark/wireshark/blob/eb5f4eea99593b92298bacecc5c9d885cc13a9ad/epan/dissectors/asn1/x509ce/CertificateExtensions.asn
class EntrustVersionInfo(Sequence):
    pass


EntrustVersionInfo.componentType = namedtype.NamedTypes(
    namedtype.NamedType('entrustVers', GeneralString()),
    namedtype.OptionalNamedType('entrustInfoFlags', BitString()),
)


class X509EntrustVersionInfo(X509Extension):
    EXT_TYPE = OID.ENTRUST_VERSION

    def __init__(self, entrust_version: str, entrust_info_flags: X509EntrustInfoFlag=None, critical: bool=False) -> None:
        self.entrust_version    = entrust_version
        self.entrust_info_flags = entrust_info_flags
        super().__init__(critical=critical)
    

    def build(self) -> rfc5280.Extension:
        entrust_info = EntrustVersionInfo()
        entrust_info['entrustVers'] = GeneralString(self.entrust_version)

        if self.entrust_info_flags is not None:
            entrust_info['entrustInfoFlags'] = self.entrust_info_flags.build()

        return super()._build(entrust_info)


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509EntrustVersionInfo':
        ext_val, _ = decoder.decode(value_bytes, asn1Spec=EntrustVersionInfo())
        ver = str(ext_val['entrustVers'])

        eif = None
        if ext_val['entrustInfoFlags'].isValue:
            eif = X509EntrustInfoFlag.parse(ext_val['entrustInfoFlags'])

        return X509EntrustVersionInfo(entrust_version=ver, entrust_info_flags=eif, critical=critical)



class IntExtension(X509Extension):
    def build(self) -> rfc5280.Extension:
        return super()._build(Integer(getattr(self, self.DATA_ATTR)))


    @classmethod
    def parse(cls, value_bytes: bytes, critical: bool) -> 'IntExtension':
        ext_val, _ = decoder.decode(value_bytes)
        return cls(**{cls.DATA_ATTR: int(ext_val), 'critical': critical})



class X509CRLNumber(IntExtension, X509Extension):
    EXT_TYPE  = OID.CRL_NUMBER
    DATA_ATTR = 'crl_number'

    def __init__(self, crl_number: int, critical: bool=False) -> None:
        self.crl_number = crl_number
        super().__init__(critical=critical)



# https://www.rfc-editor.org/rfc/rfc6066.html#section-1.1
# https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
class X509TLSFeature(Enum):
    SERVER_NAME = 0
    MAX_FRAGMENT_LENGTH = 1
    CLIENT_CERTIFICATE_URL = 2
    TRUSTED_CA_KEYS = 3
    TRUNCATED_HMAC = 4
    STATUS_REQUEST = 5
    USER_MAPPING = 6
    CLIENT_AUTHZ = 7
    SERVER_AUTHZ = 8
    CERT_TYPE = 9
    SUPPORTED_GROUPS = 10
    EC_POINT_FORMATS = 11
    SRP = 12
    SIGNATURE_ALGORITHMS = 13
    USE_SRTP = 14
    HEARTBEAT = 15
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16
    STATUS_REQUEST_V2 = 17
    SIGNED_CERTIFICATE_TIMESTAMP = 18
    CLIENT_CERTIFICATE_TYPE = 19
    SERVER_CERTIFICATE_TYPE = 20
    PADDING = 21
    ENCRYPT_THEN_MAC = 22
    EXTENDED_MASTER_SECRET = 23
    TOKEN_BINDING = 24
    CACHED_INFO = 25
    TLS_LTS = 26
    COMPRESS_CERTIFICATE = 27
    RECORD_SIZE_LIMIT = 28
    PWD_PROTECT = 29
    PWD_CLEAR = 30
    PASSWORD_SALT = 31
    TICKET_PINNING = 32
    TLS_CERT_WITH_EXTERN_PSK = 33
    DELEGATED_CREDENTIALS = 34
    SESSION_TICKET = 35
    TLMSP = 36
    TLMSP_PROXYING = 37
    TLMSP_DELEGATE = 38
    SUPPORTED_EKT_CIPHERS = 39
    PRE_SHARED_KEY = 41
    EARLY_DATA = 42
    SUPPORTED_VERSIONS = 43
    COOKIE = 44
    PSK_KEY_EXCHANGE_MODES = 45
    CERTIFICATE_AUTHORITIES = 47
    OID_FILTERS = 48
    POST_HANDSHAKE_AUTH = 49
    SIGNATURE_ALGORITHMS_CERT = 50
    KEY_SHARE = 51
    TRANSPARENCY_INFO = 52
    CONNECTION_ID_DEPRECATED = 53
    CONNECTION_ID = 54
    EXTERNAL_ID_HASH = 55
    EXTERNAL_SESSION_ID = 56
    QUIC_TRANSPORT_PARAMETERS = 57
    TICKET_REQUEST = 58
    DNSSEC_CHAIN = 59
    RENEGOTIATION_INFO = 65281



class X509TLSFeatures(X509Extension):
    EXT_TYPE = OID.TLS_FEATURES

    def __init__(self, features: List[X509TLSFeature], critical: bool=False) -> None:
        self.features = features
        super().__init__(critical=critical)
    

    def build(self) -> rfc5280.Extension:
        seqof = SequenceOf()

        for feature in self.features:
            if type(feature) is X509TLSFeature:
                feature = feature.value

            seqof.append(Integer(feature))

        return super()._build(seqof)


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509TLSFeatures':
        ext_val, _ = decoder.decode(value_bytes)
        features   = []

        for num in ext_val:
            val = int(num)
            try:
                val = X509TLSFeature(val)
            except ValueError:
                pass

            features.append(val)

        return X509TLSFeatures(features=features, critical=critical)
