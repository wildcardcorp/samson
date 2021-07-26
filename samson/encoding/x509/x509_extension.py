from samson.utilities.bytes import Bytes
from typing import List
from pyasn1_modules import rfc2459, rfc5280
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import ObjectIdentifier, OctetString, Boolean
from enum import Enum, IntFlag
from samson.core.base_object import BaseObject
from samson.encoding.tls.tls_crypto import TLSSCTList

IA5_TAGS = {
    'dns': 'dNSName',
    'ip':  'iPAddress',
    'email': 'rfc822Name',
    'uri': 'uniformResourceIdentifier'
}

INVERSE_IA5_TAGS = {v:k for k,v in IA5_TAGS.items()}


def build_general_name(name: str):
    n_type, n_value = name.split(':', 1)
    com  = rfc2459.GeneralName.componentType[IA5_TAGS[n_type.lower()]]
    name = rfc2459.GeneralName()
    com_name = com.getName()
    com_type = com.getType()

    if type(com_type) is OctetString:
        n_value = [int(part) for part in n_value.split('.')]
        n_value = bytes(n_value)

    name[com_name] = com_type.clone(n_value)

    return name


def parse_general_name(name: rfc2459.GeneralName) -> str:
    n_type = name.getName()
    value  = name[n_type]

    # Parse IP
    if type(value) is OctetString:
        value = '.'.join([str(part) for part in bytes(value)])

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



class X509ExtensionType(Enum):
    SUBJECT_KEY_IDENTIFER    = '2.5.29.14'
    KEY_USAGE                = '2.5.29.15'
    PRIVATE_KEY_USAGE_PERIOD = '2.5.29.16'
    SUBJECT_ALTERNATIVE_NAME = '2.5.29.17'
    ISSUER_ALTERNATIVE_NAME  = '2.5.29.18'
    BASIC_CONSTRAINTS        = '2.5.29.19'
    CRL_NUMBER               = '2.5.29.20'
    REASON_CODE              = '2.5.29.21'
    HOLD_INSTRUCTION_CODE    = '2.5.29.23'
    CRL_DISTRIBUTION_POINTS  = '2.5.29.31'
    CERTIFICATE_POLICIES     = '2.5.29.32'
    AUTHORITY_KEY_IDENTIFIER = '2.5.29.35'
    EXTENDED_KEY_USAGE       = '2.5.29.37'
    AUTHORITY_INFO_ACCESS    = '1.3.6.1.5.5.7.1.1'
    CERTIFICATE_TRANSPARENCY = '1.3.6.1.4.1.11129.2.4.2'


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


    def build_extension(self, value: object):
        ext = rfc2459.Extension()
        ext['extnID']    = ObjectIdentifier(self.EXT_TYPE.value)
        ext['critical']  = Boolean(self.critical)
        ext['extnValue'] = OctetString(encoder.encode(value))

        return ext


    @staticmethod
    def parse(extension: rfc5280.Extension) -> 'X509Extension':
        ext_type = X509ExtensionType(str(extension['extnID']))
        critical = bool(extension['critical'])

        for subclass in X509Extension.__subclasses__():
            if subclass.EXT_TYPE == ext_type:
                return subclass.parse(bytes(extension['extnValue']), critical)
        
        raise ValueError('Extension does not match any registered X509Extension')



class X509SubjectAlternativeName(X509Extension):
    EXT_TYPE = X509ExtensionType.SUBJECT_ALTERNATIVE_NAME

    def __init__(self, names: list, critical: bool=False) -> None:
        self.names = names
        super().__init__(critical=critical)
    

    def build_extension(self) -> rfc5280.Extension:
        san = rfc2459.SubjectAltName()

        for name in self.names:
            san.append(build_general_name(name))
        
        return super().build_extension(san)


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509SubjectAlternativeName':
        san, _ = decoder.decode(value_bytes, asn1Spec=rfc2459.SubjectAltName())
        sans   = []
        for name in san:
            sans.append(parse_general_name(name))

        return X509SubjectAlternativeName(names=sans, critical=critical)



class X509BasicConstraints(X509Extension):
    EXT_TYPE = X509ExtensionType.BASIC_CONSTRAINTS

    def __init__(self, is_ca: bool=True, critical: bool=True) -> None:
        self.is_ca = is_ca
        super().__init__(critical=critical)
    

    def build_extension(self) -> rfc5280.Extension:
        ca_value = rfc2459.BasicConstraints()
        ca_value['cA'] = self.is_ca

        return super().build_extension(ca_value)
    

    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509BasicConstraints':
        ext_val, _ = decoder.decode(value_bytes, asn1Spec=rfc2459.BasicConstraints())
        return X509BasicConstraints(is_ca=bool(ext_val['cA']), critical=critical)



class X509KeyUsage(X509Extension):
    EXT_TYPE = X509ExtensionType.KEY_USAGE

    def __init__(self, key_usage: X509KeyUsageFlag, critical: bool=True) -> None:
        self.key_usage = key_usage
        super().__init__(critical=critical)
    

    def build_extension(self) -> rfc5280.Extension:
        usage = rfc5280.KeyUsage(bin(int(self.key_usage))[2:].strip('0'))
        return super().build_extension(usage)


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509KeyUsage':
        ext_val, _ = decoder.decode(value_bytes, asn1Spec=rfc5280.KeyUsage())
        ext_val    = int(ext_val)
        ext_val    = int(bin(ext_val)[2:][::-1].zfill(9)[::-1], 2)

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
        
        return super().build_extension(ext_ku)


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509ExtendedKeyUsage':
        ext_val, _ = decoder.decode(value_bytes, asn1Spec=rfc5280.ExtKeyUsageSyntax())

        oids = []
        for key_purpose in ext_val:
            oids.append(X509ExtKeyUsageType(str(key_purpose)))
        
        return X509ExtendedKeyUsage(oids=oids, critical=critical)



class X509SubjectKeyIdentifier(X509Extension):
    EXT_TYPE = X509ExtensionType.SUBJECT_KEY_IDENTIFER

    def __init__(self, key_identifier: bytes=None, critical: bool=False) -> None:
        self.key_identifier = key_identifier
        super().__init__(critical=critical)
    

    def build_extension(self) -> rfc5280.Extension:
        ski = rfc2459.SubjectKeyIdentifier(self.key_identifier)
        return super().build_extension(ski)


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
        
        return super().build_extension(points)


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

        return super().build_extension(aki)


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

        return super().build_extension(aia)


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



class X509CertificatePolicies(X509Extension):
    EXT_TYPE = X509ExtensionType.CERTIFICATE_POLICIES

    def __init__(self, policies: List[str], critical: bool=False) -> None:
        self.policies = policies
        super().__init__(critical=critical)
    

    def build_extension(self) -> rfc5280.Extension:
        cert_policy = rfc5280.CertificatePolicies()

        for policy in self.policies:
            if type(policy) is X509CertificatePolicyType:
                policy = policy.value

            poly_info = rfc5280.PolicyInformation()
            policy_id = rfc5280.CertPolicyId(policy)
            poly_info['policyIdentifier'] = policy_id

            cert_policy.append(poly_info)

        return super().build_extension(cert_policy)


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509CertificatePolicies':
        ext_val, _ = decoder.decode(value_bytes, asn1Spec=rfc5280.CertificatePolicies())

        oids = []
        for policy_info in ext_val:
            oid = str(policy_info['policyIdentifier'])
            try:
                oid = X509CertificatePolicyType(oid)
            except ValueError:
                pass

            oids.append(oid)

        return X509CertificatePolicies(policies=oids, critical=critical)



class X509CertificateTransparency(X509Extension):
    EXT_TYPE = X509ExtensionType.CERTIFICATE_TRANSPARENCY

    def __init__(self, scts: TLSSCTList, critical: bool=False) -> None:
        self.scts = scts
        super().__init__(critical=critical)
    

    def build_extension(self) -> rfc5280.Extension:
        sct_packed = bytes(self.scts.pack())
        return super().build_extension(OctetString(sct_packed))


    @staticmethod
    def parse(value_bytes: bytes, critical: bool) -> 'X509CertificateTransparency':
        ext_val, _ = decoder.decode(value_bytes)
        scts, _    = TLSSCTList.unpack(Bytes(bytes(ext_val)))
        return X509CertificateTransparency(scts=scts, critical=critical)
