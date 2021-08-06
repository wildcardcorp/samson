from datetime import datetime, timezone
from pyasn1.type.char import IA5String, GeneralString
from samson.utilities.bytes import Bytes
from typing import List
from pyasn1_modules import rfc2459, rfc5280
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import BitString, Integer, Null, ObjectIdentifier, OctetString, Boolean, SequenceOf, Sequence
from pyasn1.type import namedtype
from pyasn1.type.useful import UTCTime
from enum import Enum, IntFlag
from samson.core.base_object import BaseObject
from samson.encoding.tls.tls_crypto import TLSSCTList
from samson.encoding.asn1 import rdn_to_str, parse_rdn

IA5_TAGS = {
    'dns': 'dNSName',
    'ip':  'iPAddress',
    'email': 'rfc822Name',
    'uri': 'uniformResourceIdentifier',
    'dir': 'directoryName',
    'othername': 'otherName'
}

INVERSE_IA5_TAGS = {v:k for k,v in IA5_TAGS.items()}


def build_general_name(name: str):
    n_type, n_value = name.split(':', 1)
    ia5_type = IA5_TAGS[n_type.lower()]
    com  = rfc2459.GeneralName.componentType[ia5_type]
    name = rfc2459.GeneralName()
    com_name = com.getName()
    com_type = com.getType()

    if type(com_type) is OctetString:
        n_value = [int(part) for part in n_value.split('.')]
        n_value = bytes(n_value)
        name[com_name] = com_type.clone(n_value)

    elif type(com_type) in (rfc5280.Name, rfc2459.Name):
        n_value = parse_rdn(n_value)
        name = rfc5280.GeneralName()
        sub_name = name[ia5_type].clone()
        sub_name['rdnSequence'] = n_value
        name[com_name] = sub_name

    else:
        name[com_name] = com_type.clone(n_value)

    return name


def parse_general_name(name: rfc2459.GeneralName) -> str:
    n_type = name.getName()
    value  = name[n_type]

    # Parse IP
    if type(value) is OctetString:
        value = '.'.join([str(part) for part in bytes(value)])

    elif type(value) in (rfc5280.Name, rfc2459.Name):
        for key in ['rdnSequence', '']:
            if key in value:
                break

        value = rdn_to_str(value[key])
    
    elif type(value) is rfc2459.AnotherName:
        value = value['value']

    return f'{INVERSE_IA5_TAGS[n_type]}:{str(value)}'



def build_crl_dist_point(names: list) -> 'rfc5280.DistributionPoint':
    points = rfc5280.CRLDistributionPoints()
    point  = points[0].clone()
    point_name = point['distributionPoint'].clone()

    gen_names = point_name['fullName'].clone()

    for name in names:
        gen_names.append(build_general_name(name))

    point_name['fullName']     = gen_names
    point['distributionPoint'] = point_name

    return point


def merge_enums(name: str, sub_enums: list):
    """
    References:
        https://stackoverflow.com/questions/33679930/how-to-extend-python-enum
    """
    import itertools
    merged = [[(prefix + kv.name, kv.value) for kv in enum] for prefix, enum in itertools.chain(sub_enums)]
    merged = [item for sublist in merged for item in sublist]
    return Enum(name, merged)


class MicrosoftCertificateServicesOID(Enum):
    CERTIFICATE_SERVICES_CA_VERSION = '1.3.6.1.4.1.311.21.1'
    szOID_CERTSRV_PREVIOUS_CERT_HASH = '1.3.6.1.4.1.311.21.2'
    szOID_CRL_VIRTUAL_BASE = '1.3.6.1.4.1.311.21.3'
    szOID_CRL_NEXT_PUBLISH = '1.3.6.1.4.1.311.21.4'
    szOID_KP_CA_EXCHANGE = '1.3.6.1.4.1.311.21.5'
    szOID_KP_KEY_RECOVERY_AGENT = '1.3.6.1.4.1.311.21.6'
    szOID_CERTIFICATE_TEMPLATE = '1.3.6.1.4.1.311.21.7'
    szOID_ENTERPRISE_OID_ROOT = '1.3.6.1.4.1.311.21.8'
    szOID_RDN_DUMMY_SIGNER = '1.3.6.1.4.1.311.21.9'
    szOID_APPLICATION_CERT_POLICIES = '1.3.6.1.4.1.311.21.10'
    szOID_APPLICATION_POLICY_MAPPINGS = '1.3.6.1.4.1.311.21.11'
    szOID_APPLICATION_POLICY_CONSTRAINTS = '1.3.6.1.4.1.311.21.12'
    szOID_ARCHIVED_KEY_ATTR = '1.3.6.1.4.1.311.21.13'
    szOID_CRL_SELF_CDP = '1.3.6.1.4.1.311.21.14'
    szOID_REQUIRE_CERT_CHAIN_POLICY = '1.3.6.1.4.1.311.21.15'
    szOID_ARCHIVED_KEY_CERT_HASH = '1.3.6.1.4.1.311.21.16'
    szOID_ISSUED_CERT_HASH = '1.3.6.1.4.1.311.21.17'
    szOID_DS_EMAIL_REPLICATION = '1.3.6.1.4.1.311.21.19'
    szOID_REQUEST_CLIENT_INFO = '1.3.6.1.4.1.311.21.20'
    szOID_ENCRYPTED_KEY_HASH = '1.3.6.1.4.1.311.21.21'
    szOID_CERTSRV_CROSSCA_VERSION = '1.3.6.1.4.1.311.21.22'


class NetscapeCertificateOID(Enum):
    CERTIFICATE_TYPE = '2.16.840.1.113730.1.1'
    BASE_URL = '2.16.840.1.113730.1.2'
    REVOCATION_URL = '2.16.840.1.113730.1.3'
    CA_REVOCATION_URL = '2.16.840.1.113730.1.4'
    CA_CRL_URL = '2.16.840.1.113730.1.5'
    CA_CERT = '2.16.840.1.113730.1.6'
    RENEWAL_URL = '2.16.840.1.113730.1.7'
    CA_POLICY_URL = '2.16.840.1.113730.1.8'
    HOMEPAGE_URL = '2.16.840.1.113730.1.9'
    ENTITY_LOGO = '2.16.840.1.113730.1.10'
    USER_PICTURE = '2.16.840.1.113730.1.11'
    SSL_SERVER_NAME = '2.16.840.1.113730.1.12'
    COMMENT = '2.16.840.1.113730.1.13'
    LOST_PASSWORD_URL = '2.16.840.1.113730.1.14'
    CERT_RENEWAL_TIME = '2.16.840.1.113730.1.15'


class StandardExtensionType(Enum):
    SUBJECT_DIRECTORY_ATTRIBUTES = '2.5.29.9'
    SUBJECT_KEY_IDENTIFER        = '2.5.29.14'
    KEY_USAGE                    = '2.5.29.15'
    PRIVATE_KEY_USAGE_PERIOD     = '2.5.29.16'
    SUBJECT_ALTERNATIVE_NAME     = '2.5.29.17'
    ISSUER_ALTERNATIVE_NAME      = '2.5.29.18'
    BASIC_CONSTRAINTS            = '2.5.29.19'
    CRL_NUMBER                   = '2.5.29.20'
    REASON_CODE                  = '2.5.29.21'
    EXPIRATION_DATE              = '2.5.29.22'
    HOLD_INSTRUCTION_CODE        = '2.5.29.23'
    INVALIDITY_DATE              = '2.5.29.24'
    DELTA_CRL_INDICATOR          = '2.5.29.27'
    ISSUING_DISTRIBUTION_POINT   = '2.5.29.28'
    CRL_DISTRIBUTION_POINTS      = '2.5.29.31'
    CERTIFICATE_POLICIES         = '2.5.29.32'
    AUTHORITY_KEY_IDENTIFIER     = '2.5.29.35'
    POLICY_CONSTRAINTS           = '2.5.29.36'
    EXTENDED_KEY_USAGE           = '2.5.29.37'
    AUTHORITY_ATTR_IDENTIFIER    = '2.5.29.38'
    ROLE_SPEC_CERT_ID            = '2.5.29.39'
    CRL_STREAM_IDENTIFIER        = '2.5.29.40'
    DELEGATED_NAME_CONSTRAINTS   = '2.5.29.42'
    TIME_SPECIFICATION           = '2.5.29.43'
    CRL_SCOPE                    = '2.5.29.44'
    STATUS_REFERRALS             = '2.5.29.45'
    FRESHEST_CRL                 = '2.5.29.46'
    INHIBIT_ANY_POLICY           = '2.5.29.54'
    AUTHORITY_INFO_ACCESS        = '1.3.6.1.5.5.7.1.1'
    SUBJECT_INFORMATION_ACCESS   = '1.3.6.1.5.5.7.1.11'
    TLS_FEATURE                  = '1.3.6.1.5.5.7.1.24'
    OCSP_NO_CHECK                = '1.3.6.1.5.5.7.48.1.5'
    CERTIFICATE_TRANSPARENCY     = '1.3.6.1.4.1.11129.2.4.2'
    CT_PRECERTIFICATE_POISON     = '1.3.6.1.4.1.11129.2.4.3'
    ENTRUST_VERSION              = '1.2.840.113533.7.65.0'


X509ExtensionType = merge_enums('X509ExtensionType',
    [
        ('', StandardExtensionType),
        ('MICROSOFT_', MicrosoftCertificateServicesOID),
        ('NETSCAPE_', NetscapeCertificateOID)
    ]
)



class X509ExtKeyUsageType(Enum):
    TLS_WEB_SERVER_AUTHENTICATION = '1.3.6.1.5.5.7.3.1'
    TLS_WEB_CLIENT_AUTHENTICATION = '1.3.6.1.5.5.7.3.2'
    CODE_SIGNING = '1.3.6.1.5.5.7.3.3'
    EMAIL_PROTECTION = '1.3.6.1.5.5.7.3.4'
    IPSEC_END_SYSTEM = '1.3.6.1.5.5.7.3.5'
    IPSEC_TUNNEL = '1.3.6.1.5.5.7.3.6'
    IPSEC_USER = '1.3.6.1.5.5.7.3.7'
    TIMESTAMPING = '1.3.6.1.5.5.7.3.8'
    OCSP_SIGNING = '1.3.6.1.5.5.7.3.9'
    DVCS_SERVER = '1.3.6.1.5.5.7.3.10'
    SBGP_CERT_AA_SERVER_AUTH = '1.3.6.1.5.5.7.3.11'
    SCVP_RESPONDER = '1.3.6.1.5.5.7.3.12'
    EAP_OVER_PPP = '1.3.6.1.5.5.7.3.13'
    EAP_OVER_LAN = '1.3.6.1.5.5.7.3.14'
    SCVP_SERVER = '1.3.6.1.5.5.7.3.15'
    SCVP_CLIENT = '1.3.6.1.5.5.7.3.16'
    IPSEC_IKE = '1.3.6.1.5.5.7.3.17'
    CAP_WAP_AC = '1.3.6.1.5.5.7.3.18'
    CAP_WAP_WTP = '1.3.6.1.5.5.7.3.19'
    SIP_DOMAIN = '1.3.6.1.5.5.7.3.20'
    SECURE_SHELL_CLIENT = '1.3.6.1.5.5.7.3.21'
    SECURE_SHELL_SERVER = '1.3.6.1.5.5.7.3.22'
    RPC_TLS_CLIENT = '1.3.6.1.5.5.7.3.33'
    RPC_TLS_SERVER = '1.3.6.1.5.5.7.3.34'
    NETSCAPE_SERVER_GATED_CRYPTO  = '2.16.840.1.113730.4.1'
    VERISIGN_SERVER_GATED_CRYPTO  = '2.16.840.1.113733.1.8.1' 
    MICROSOFT_SERVER_GATED_CRYPTO = '1.3.6.1.4.1.311.10.3.3'


class X509KeyUsageFlag(IntFlag):
    DIGITAL_SIGNATURE = 2**8
    NON_REPUDIATION   = 2**7
    KEY_ENCIPHERMENT  = 2**6
    DATA_ENCIPHERMENT = 2**5
    KEY_AGREEMENT     = 2**4
    KEY_CERT_SIGN     = 2**3
    CRL_SIGN          = 2**2
    ENCIPHER_ONLY     = 2**1
    DECIPHER_ONLY     = 2**0



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


    def build_extension(self) -> rfc5280.Extension:
        """
        For arbitrary extensions.
        """
        oid = self.oid
        if type(oid) is X509ExtensionType:
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

        ext_type = X509ExtensionType(ext_type)

        for subclass in X509Extension.__subclasses__():
            if subclass.EXT_TYPE == ext_type:
                return subclass.parse(bytes(extension['extnValue']), critical)

        ext = X509Extension(critical=critical)
        ext.oid = ext_type
        ext.data = bytes(extension['extnValue'])
        return ext



class _AlternateName(object):
    EXT_TYPE = None

    def __init__(self, names: list, critical: bool=False, allow_empty: bool=True) -> None:
        self.names = names
        self.allow_empty = allow_empty
        super().__init__(critical=critical)
    

    def build_extension(self) -> rfc5280.Extension:
        san = self.NAME_SPEC()

        for name in self.names:
            san.append(build_general_name(name))

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
            sans.append(parse_general_name(name))

        return cls(names=sans, critical=critical)


class X509SubjectAlternativeName(_AlternateName, X509Extension):
    EXT_TYPE  = X509ExtensionType.SUBJECT_ALTERNATIVE_NAME
    NAME_SPEC = rfc2459.SubjectAltName


class X509IssuerAlternativeName(_AlternateName, X509Extension):
    EXT_TYPE  = X509ExtensionType.ISSUER_ALTERNATIVE_NAME
    NAME_SPEC = rfc2459.IssuerAltName



class X509BasicConstraints(X509Extension):
    EXT_TYPE = X509ExtensionType.BASIC_CONSTRAINTS

    def __init__(self, is_ca: bool=True, path_len: int=None, critical: bool=True) -> None:
        self.is_ca    = is_ca
        self.path_len = path_len
        super().__init__(critical=critical)
    

    def build_extension(self) -> rfc5280.Extension:
        ca_value = rfc2459.BasicConstraints()
        ca_value['cA'] = self.is_ca

        if self.path_len is not None:
            ca_value['pathLenConstraint'] = self.path_len

        return super()._build(ca_value)
    

    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509BasicConstraints':
        ext_val, _ = decoder.decode(value_bytes, asn1Spec=rfc2459.BasicConstraints())

        path_len = ext_val['pathLenConstraint']

        if path_len.isValue:
            path_len = int(path_len)
        else:
            path_len = None

        return X509BasicConstraints(is_ca=bool(ext_val['cA']), path_len=path_len, critical=critical)


def _build_from_int_flag(val):
    return bin(int(val))[2:].strip('0')


def _parse_int_flag_from_asn1(val, size):
    val = int(val)
    val = int(bin(val)[2:][::-1].zfill(size)[::-1], 2)
    return val



class X509KeyUsage(X509Extension):
    EXT_TYPE = X509ExtensionType.KEY_USAGE

    def __init__(self, key_usage: X509KeyUsageFlag, critical: bool=True) -> None:
        self.key_usage = key_usage
        super().__init__(critical=critical)
    

    def build_extension(self) -> rfc5280.Extension:
        usage = rfc5280.KeyUsage(_build_from_int_flag(self.key_usage))
        return super()._build(usage)


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509KeyUsage':
        ext_val, _ = decoder.decode(value_bytes, asn1Spec=rfc5280.KeyUsage())
        ext_val = _parse_int_flag_from_asn1(ext_val, 9)

        return X509KeyUsage(key_usage=X509KeyUsageFlag(ext_val), critical=critical)



class X509ExtendedKeyUsage(X509Extension):
    EXT_TYPE = X509ExtensionType.EXTENDED_KEY_USAGE

    def __init__(self, oids: List[X509ExtKeyUsageType], critical: bool=False) -> None:
        self.oids = oids
        super().__init__(critical=critical)
    

    def build_extension(self) -> rfc5280.Extension:
        ext_ku = rfc5280.ExtKeyUsageSyntax()

        for oid in self.oids:
            if type(oid) is X509ExtKeyUsageType:
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
                oid = X509ExtKeyUsageType(oid)
            except ValueError:
                pass

            oids.append(oid)
        
        return X509ExtendedKeyUsage(oids=oids, critical=critical)



class X509SubjectKeyIdentifier(X509Extension):
    EXT_TYPE = X509ExtensionType.SUBJECT_KEY_IDENTIFER

    def __init__(self, key_identifier: bytes=None, critical: bool=False) -> None:
        self.key_identifier = key_identifier
        super().__init__(critical=critical)
    

    def build_extension(self) -> rfc5280.Extension:
        ski = rfc2459.SubjectKeyIdentifier(self.key_identifier)
        return super()._build(ski)


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509SubjectKeyIdentifier':
        ext_val, _ = decoder.decode(value_bytes, asn1Spec=rfc2459.SubjectKeyIdentifier())
        return X509SubjectKeyIdentifier(key_identifier=bytes(ext_val), critical=critical)



class X509CRLDistributionPoints(X509Extension):
    EXT_TYPE = X509ExtensionType.CRL_DISTRIBUTION_POINTS

    def __init__(self, names: List[str], critical: bool=False) -> None:
        self.names = names
        super().__init__(critical=critical)
    

    def build_extension(self) -> rfc5280.Extension:
        points = rfc5280.CRLDistributionPoints()
        for name in self.names:
            points.append(build_crl_dist_point([name]))
        
        return super()._build(points)


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509CRLDistributionPoints':
        ext_val, _ = decoder.decode(value_bytes, asn1Spec=rfc5280.CRLDistributionPoints())

        dist_points = []
        for point in ext_val:
            for name in point['distributionPoint']['fullName']:
                dist_points.append(parse_general_name(name))

        return X509CRLDistributionPoints(names=dist_points, critical=critical)



class X509AuthorityKeyIdentifier(X509Extension):
    EXT_TYPE = X509ExtensionType.AUTHORITY_KEY_IDENTIFIER

    def __init__(self, key_identifier: bytes, authority_cert_issuer: List[str], authority_cert_serial_number: int, critical: bool=False) -> None:
        self.key_identifier = key_identifier
        self.authority_cert_issuer = authority_cert_issuer
        self.authority_cert_serial_number = authority_cert_serial_number
        super().__init__(critical=critical)
    

    def build_extension(self) -> rfc5280.Extension:
        aki = rfc5280.AuthorityKeyIdentifier()

        if self.key_identifier is not None:
            aki['keyIdentifier'] = aki['keyIdentifier'].clone(self.key_identifier)

        if self.authority_cert_issuer is not None:
            gen_names = aki['authorityCertIssuer'].clone()

            for name in self.authority_cert_issuer:
                gen_names.append(build_general_name(name))

            aki['authorityCertIssuer'] = gen_names

        if self.authority_cert_serial_number is not None:
            aki['authorityCertSerialNumber'] = aki['authorityCertSerialNumber'].clone(self.authority_cert_serial_number)

        return super()._build(aki)


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509AuthorityKeyIdentifier':
        ext_val, _ = decoder.decode(value_bytes, asn1Spec=rfc5280.AuthorityKeyIdentifier())

        key_identifier = bytes(ext_val['keyIdentifier']) if ext_val['keyIdentifier'].isValue else None
        authority_cert_issuer = [parse_general_name(name) for name in ext_val['authorityCertIssuer']]
        authority_cert_serial_number = int(ext_val['authorityCertSerialNumber']) if ext_val['authorityCertSerialNumber'].isValue else None

        return X509AuthorityKeyIdentifier(key_identifier=key_identifier, authority_cert_issuer=authority_cert_issuer, authority_cert_serial_number=authority_cert_serial_number, critical=critical)


class X509AccessDescriptorType(Enum):
    OSCP          = '1.3.6.1.5.5.7.48.1'
    CA_ISSUER     = '1.3.6.1.5.5.7.48.2'
    TIMESTAMPING  = '1.3.6.1.5.5.7.48.3'
    CA_REPOSITORY = '1.3.6.1.5.5.7.48.5'



class X509AccessDescription(BaseObject):
    def __init__(self, access_method: X509AccessDescriptorType, access_location: 'str') -> None:
        self.access_method = access_method
        self.access_location = access_location


class X509AuthorityInfoAccess(X509Extension):
    EXT_TYPE = X509ExtensionType.AUTHORITY_INFO_ACCESS

    def __init__(self, access_descriptions: List[X509AccessDescription], critical: bool=False) -> None:
        self.access_descriptions = access_descriptions
        super().__init__(critical=critical)


    def build_extension(self) -> rfc5280.Extension:
        aia   = rfc5280.AuthorityInfoAccessSyntax()

        for access_desc in self.access_descriptions:
            acc_desc = rfc5280.AccessDescription()
            acc_desc['accessMethod']   = ObjectIdentifier(access_desc.access_method.value)
            acc_desc['accessLocation'] = build_general_name(access_desc.access_location)
            aia.append(acc_desc)

        return super()._build(aia)


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509AuthorityInfoAccess':
        ext_val, _ = decoder.decode(value_bytes, asn1Spec=rfc5280.AuthorityInfoAccessSyntax())

        access_descriptions = []
        for access_desc in ext_val:
            access_method   = X509AccessDescriptorType(str(access_desc['accessMethod']))
            access_location = parse_general_name(access_desc['accessLocation'])
            access_descriptions.append(X509AccessDescription(access_method, access_location))

        return X509AuthorityInfoAccess(access_descriptions=access_descriptions, critical=critical)


class X509CertificatePolicyType(Enum):
    EXTENDED_VALIDATION    = '2.23.140.1.1'
    DOMAIN_VALIDATED       = '2.23.140.1.2.1'
    ORGANIZATION_VALIDATED = '2.23.140.1.2.2'
    INDIVIDUAL_VALIDATED   = '2.23.140.1.2.3'
    EXTENDED_VALIDATION_CODE_SIGNING = '2.23.140.1.3'
    CODE_SIGNING_REQUIREMENTS = '2.23.140.1.4'
    SMIME = '2.23.140.1.5'
    GOOGLE_TRUST_SERVICES = '1.3.6.1.4.1.11129.2.5.3'
    VERISIGN_EXTENDED_VALIDATION = '2.16.840.1.113733.1.7.23.6'
    ANY = '2.5.29.32.0'
    FRENCH_GOV_CA = '1.2.250.1.121.1.1.1'
    ISRG_DOMAIN_VALIDATED = '1.3.6.1.4.1.44947.1.1.1'


class X509CertificatePolicyQualifierType(Enum):
    CERTIFICATE_PRACTICE_STATEMENT = '1.3.6.1.5.5.7.2.1'
    USER_NOTICE = '1.3.6.1.5.5.7.2.2'


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



class X509UserNotice(X509PolicyQualifier):
    QUALIFIER_TYPE = X509CertificatePolicyQualifierType.USER_NOTICE
    DATA_SPEC      = rfc5280.UserNotice

    def __init__(self, explicit_text: str=None, org_name: str=None, notice_nums: List[int]=None) -> None:
        self.explicit_text = explicit_text
        self.org_name      = org_name
        self.notice_nums   = notice_nums


    def build_data(self) -> object:
        data = rfc5280.UserNotice()

        if self.explicit_text is not None:
            data['explicitText']['utf8String'] = data['explicitText']['utf8String'] .clone(self.explicit_text)
        
        notice_ref = data['noticeRef']
        if self.org_name is not None:
            notice_ref['organization']['utf8String'] = notice_ref['organization']['utf8String'].clone(self.org_name)
        
        if self.notice_nums is not None:
            notice_ref['noticeNumbers'].extend(self.notice_nums)

        return data


    @staticmethod
    def parse_data(data: object) -> str:
        ex_text = data['explicitText']

        if ex_text.isValue:
            ex_text = str(ex_text[ex_text.getName()])
        else:
            ex_text = None

        notice_ref = data['noticeRef']
        org_name   = notice_ref['organization']

        if org_name.isValue:
            org_name = str(org_name[org_name.getName()])
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
    EXT_TYPE = X509ExtensionType.CERTIFICATE_POLICIES

    def __init__(self, policies: List[X509CertificatePolicy], critical: bool=False) -> None:
        self.policies = policies
        super().__init__(critical=critical)
    

    def build_extension(self) -> rfc5280.Extension:
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
    EXT_TYPE = X509ExtensionType.MICROSOFT_szOID_APPLICATION_CERT_POLICIES


class X509CertificateTransparency(X509Extension):
    EXT_TYPE = X509ExtensionType.CERTIFICATE_TRANSPARENCY

    def __init__(self, scts: TLSSCTList, critical: bool=False) -> None:
        self.scts = scts
        super().__init__(critical=critical)
    

    def build_extension(self) -> rfc5280.Extension:
        sct_packed = bytes(self.scts.pack())
        return super()._build(OctetString(sct_packed))


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509CertificateTransparency':
        ext_val, _ = decoder.decode(value_bytes)
        scts, _    = TLSSCTList.unpack(Bytes(bytes(ext_val)))
        return X509CertificateTransparency(scts=scts, critical=critical)



class X509CertificateTransparencyPoison(X509Extension):
    EXT_TYPE = X509ExtensionType.CT_PRECERTIFICATE_POISON

    def __init__(self, critical: bool=True) -> None:
        super().__init__(critical=critical)
    

    def build_extension(self) -> rfc5280.Extension:
        return super()._build(Null)


    @staticmethod
    def parse(_value_bytes: bytes, critical: bool) -> 'X509CertificateTransparencyPoison':
        return X509CertificateTransparencyPoison(critical=critical)



class X509PrivateKeyUsagePeriod(X509Extension):
    EXT_TYPE = X509ExtensionType.PRIVATE_KEY_USAGE_PERIOD

    def __init__(self, not_before: datetime=None, not_after: datetime=None, critical: bool=False) -> None:
        self.not_before = not_before
        self.not_after  = not_after
        super().__init__(critical=critical)
    

    def build_extension(self) -> rfc5280.Extension:
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
    EXT_TYPE = X509ExtensionType.POLICY_CONSTRAINTS

    def __init__(self, require_explicit_policy: int=None, inhibit_policy_mapping: int=None, critical: bool=True) -> None:
        self.require_explicit_policy = require_explicit_policy
        self.inhibit_policy_mapping  = inhibit_policy_mapping
        super().__init__(critical=critical)
    

    def build_extension(self) -> rfc5280.Extension:
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
    def build_extension(self) -> rfc5280.Extension:
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
    EXT_TYPE  = X509ExtensionType.NETSCAPE_COMMENT
    DATA_ATTR = 'comment'

    def __init__(self, comment: str, critical: bool=False) -> None:
        self.comment = comment
        super().__init__(critical=critical)


class X509NetscapeBaseURL(_NetscapeURLExtension, X509Extension):
    EXT_TYPE  = X509ExtensionType.NETSCAPE_BASE_URL

class X509NetscapeRevocationURL(_NetscapeURLExtension, X509Extension):
    EXT_TYPE  = X509ExtensionType.NETSCAPE_REVOCATION_URL

class X509NetscapeCARevocationURL(_NetscapeURLExtension, X509Extension):
    EXT_TYPE  = X509ExtensionType.NETSCAPE_CA_REVOCATION_URL

class X509NetscapeRenewalURL(_NetscapeURLExtension, X509Extension):
    EXT_TYPE  = X509ExtensionType.NETSCAPE_RENEWAL_URL

class X509NetscapeCAPolicyURL(_NetscapeURLExtension, X509Extension):
    EXT_TYPE  = X509ExtensionType.NETSCAPE_CA_POLICY_URL

class X509NetscapeSSLServerName(_NetscapeURLExtension, X509Extension):
    EXT_TYPE  = X509ExtensionType.NETSCAPE_SSL_SERVER_NAME


class X509MicrosoftCSCAVersion(X509Extension):
    EXT_TYPE  = X509ExtensionType.MICROSOFT_CERTIFICATE_SERVICES_CA_VERSION

    def __init__(self, version: int, critical: bool=False) -> None:
        self.version = version
        super().__init__(critical=critical)
    

    def build_extension(self) -> rfc5280.Extension:
        return super()._build(Integer(self.version))


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509MicrosoftCSCAVersion':
        ext_val, _ = decoder.decode(value_bytes)
        return X509MicrosoftCSCAVersion(version=int(ext_val), critical=critical)


class X509MicrosoftCSPreviousHash(X509Extension):
    EXT_TYPE  = X509ExtensionType.MICROSOFT_szOID_CERTSRV_PREVIOUS_CERT_HASH

    def __init__(self, hash: bytes, critical: bool=False) -> None:
        self.hash = hash
        super().__init__(critical=critical)
    

    def build_extension(self) -> rfc5280.Extension:
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
    EXT_TYPE  = X509ExtensionType.MICROSOFT_szOID_CERTIFICATE_TEMPLATE

    def __init__(self, template_id: str, major_version: int, minor_version: int, critical: bool=False) -> None:
        self.template_id   = template_id
        self.major_version = major_version
        self.minor_version = minor_version
        super().__init__(critical=critical)
    

    def build_extension(self) -> rfc5280.Extension:
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



class X509NetscapeCertTypeFlag(IntFlag):
    SSL_CLIENT        = 2**7
    SSL_SERVER        = 2**6
    SMIME             = 2**5
    OBJECT_SIGNING    = 2**4
    RESERVED          = 2**3
    SSL_CA            = 2**2
    SMIME_CA          = 2**1
    OBJECT_SIGNING_CA = 2**0


class X509NetscapeCertificateType(X509Extension):
    EXT_TYPE = X509ExtensionType.NETSCAPE_CERTIFICATE_TYPE

    def __init__(self, cert_type: X509NetscapeCertTypeFlag, critical: bool=False) -> None:
        self.cert_type = cert_type
        super().__init__(critical=critical)
    

    def build_extension(self) -> rfc5280.Extension:
        usage = BitString(_build_from_int_flag(self.cert_type))
        return super()._build(usage)


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509NetscapeCertificateType':
        ext_val, _ = decoder.decode(value_bytes)
        ext_val    = _parse_int_flag_from_asn1(ext_val, 8)

        return X509NetscapeCertificateType(cert_type=X509NetscapeCertTypeFlag(ext_val), critical=critical)

# I honestly cannot find the last two bits
class X509EntrustInfoFlag(IntFlag):
    KEY_UPDATE_ALLOWED  = 2**7
    NEW_EXTENSIONS      = 2**6
    PKIX_CERTIFICATE    = 2**5
    ENTERPRISE_CATEGORY = 2**4
    WEB_CATEGORY        = 2**3
    SET_CATEGORY        = 2**2


# https://github.com/wireshark/wireshark/blob/eb5f4eea99593b92298bacecc5c9d885cc13a9ad/epan/dissectors/asn1/x509ce/CertificateExtensions.asn
class EntrustVersionInfo(Sequence):
    pass


EntrustVersionInfo.componentType = namedtype.NamedTypes(
    namedtype.NamedType('entrustVers', GeneralString()),
    namedtype.OptionalNamedType('entrustInfoFlags', BitString()),
)


class X509EntrustVersionInfo(X509Extension):
    EXT_TYPE = X509ExtensionType.ENTRUST_VERSION

    def __init__(self, entrust_version: str, entrust_info_flags: X509EntrustInfoFlag=None, critical: bool=False) -> None:
        self.entrust_version    = entrust_version
        self.entrust_info_flags = entrust_info_flags
        super().__init__(critical=critical)
    

    def build_extension(self) -> rfc5280.Extension:
        entrust_info = EntrustVersionInfo()
        entrust_info['entrustVers'] = GeneralString(self.entrust_version)

        if self.entrust_info_flags is not None:
            entrust_info['entrustInfoFlags'] = BitString(_build_from_int_flag(self.entrust_info_flags))

        return super()._build(entrust_info)


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509EntrustVersionInfo':
        ext_val, _ = decoder.decode(value_bytes, asn1Spec=EntrustVersionInfo())
        ver = str(ext_val['entrustVers'])

        eif = None
        if ext_val['entrustInfoFlags'].isValue:
            eif = X509EntrustInfoFlag(_parse_int_flag_from_asn1(ext_val['entrustInfoFlags'], 8))

        return X509EntrustVersionInfo(entrust_version=ver, entrust_info_flags=eif, critical=critical)
