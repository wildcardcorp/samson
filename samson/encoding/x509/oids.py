from enum import Enum


def merge_enums(name: str, sub_enums: list):
    """
    References:
        https://stackoverflow.com/questions/33679930/how-to-extend-python-enum
    """
    import itertools
    merged = [[(prefix + kv.name, kv.value) for kv in enum] for prefix, enum in itertools.chain(sub_enums)]
    merged = [item for sublist in merged for item in sublist]
    return Enum(name, merged)



class _OID(Enum):

    def __eq__(self, other):
        return self.value == other.value

    @staticmethod
    def prefix():
        return ''

    @staticmethod
    def build_oid_enum():
        return merge_enums('OID',
            [(subclass.prefix(), subclass) for subclass in _OID.__subclasses__()]
        )




class MicrosoftCertificateServicesOID(_OID):
    @staticmethod
    def prefix():
        return 'MICROSOFT_'

    szOID_OS_VERSION = '1.3.6.1.4.1.311.13.2.3'
    SPC_CERT_EXTENSIONS_OBJID = '1.3.6.1.4.1.311.2.1.14'
    szOID_ENROLLMENT_CSP_PROVIDER = '1.3.6.1.4.1.311.13.2.2'
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


class NetscapeCertificateOID(_OID):
    @staticmethod
    def prefix():
        return 'NETSCAPE_'


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


class StandardExtensionType(_OID):
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
    LOGO_TYPE                    = '1.3.6.1.5.5.7.1.12'
    TLS_FEATURES                 = '1.3.6.1.5.5.7.1.24'
    OCSP_NO_CHECK                = '1.3.6.1.5.5.7.48.1.5'
    CERTIFICATE_TRANSPARENCY     = '1.3.6.1.4.1.11129.2.4.2'
    CT_PRECERTIFICATE_POISON     = '1.3.6.1.4.1.11129.2.4.3'
    ENTRUST_VERSION              = '1.2.840.113533.7.65.0'


class X509ExtKeyUsageType(_OID):
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
    MICROSOFT_SMARTCARD_LOGON = '1.3.6.1.4.1.311.20.2.2'


class X509AccessDescriptorType(_OID):
    @staticmethod
    def prefix():
        return 'AD_'

    OSCP          = '1.3.6.1.5.5.7.48.1'
    CA_ISSUER     = '1.3.6.1.5.5.7.48.2'
    TIMESTAMPING  = '1.3.6.1.5.5.7.48.3'
    CA_REPOSITORY = '1.3.6.1.5.5.7.48.5'



class X509CertificatePolicyType(_OID):
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


class X509CertificatePolicyQualifierType(_OID):
    CERTIFICATE_PRACTICE_STATEMENT = '1.3.6.1.5.5.7.2.1'
    USER_NOTICE = '1.3.6.1.5.5.7.2.2'


class OtherNameOID(_OID):
    KISA_IDENTIFYDATA = '1.2.410.200004.10.1.1'
    USER_PRINCIPAL_NAME = '1.3.6.1.4.1.311.20.2.3'
    KERBEROS_PRINCIPAL_NAME = '1.3.6.1.5.2.2'
    JABBER_ID = '1.3.6.1.5.5.7.8.5'


# https://www.ietf.org/rfc/rfc5698.txt
class HashType(_OID):
    MD2    = '1.2.840.113549.2.2'
    MD5    = '1.2.840.113549.2.5'
    SHA1   = '1.3.14.3.2.26'
    SHA224 = '2.16.840.1.101.3.4.2.4'
    SHA256 = '2.16.840.1.101.3.4.2.1'
    SHA384 = '2.16.840.1.101.3.4.2.2'
    SHA512 = '2.16.840.1.101.3.4.2.3'


# https://tools.ietf.org/html/rfc8017#appendix-A.2.4
class SigningAlgOID(_OID):
    MD2_WITH_RSA_ENCRYPTION        = '1.2.840.113549.1.1.2'
    MD5_WITH_RSA_ENCRYPTION        = '1.2.840.113549.1.1.4'
    SHA1_WITH_RSA_ENCRYPTION       = '1.2.840.113549.1.1.5'
    SHA224_WITH_RSA_ENCRYPTION     = '1.2.840.113549.1.1.14'
    SHA256_WITH_RSA_ENCRYPTION     = '1.2.840.113549.1.1.11'
    SHA384_WITH_RSA_ENCRYPTION     = '1.2.840.113549.1.1.12'
    SHA512_WITH_RSA_ENCRYPTION     = '1.2.840.113549.1.1.13'
    SHA512_224_WITH_RSA_ENCRYPTION = '1.2.840.113549.1.1.15'
    SHA512_256_WITH_RSA_ENCRYPTION = '1.2.840.113549.1.1.16'
    ECDSA_WITH_SHA1                = '1.2.840.10045.4.1'
    ECDSA_WITH_SHA224              = '1.2.840.10045.4.3.1'
    ECDSA_WITH_SHA256              = '1.2.840.10045.4.3.2'
    ECDSA_WITH_SHA384              = '1.2.840.10045.4.3.3'
    ECDSA_WITH_SHA512              = '1.2.840.10045.4.3.4'
    ID_DSA_WITH_SHA1               = '1.2.840.10040.4.3'
    ID_DSA_WITH_SHA224             = '2.16.840.1.101.3.4.3.1'
    ID_DSA_WITH_SHA256             = '2.16.840.1.101.3.4.3.2'


class MiscOID(_OID):
    RC2_CBC            = '1.2.840.113549.3.2'
    RC4                = '1.2.840.113549.3.4'
    DES_CBC            = '1.3.14.3.2.7'
    DES_EDE3_CBC       = '1.2.840.113549.3.7'
    EXTENSION_REQUEST  = '1.2.840.113549.1.9.14'
    SMIME_CAPABILITIES = '1.2.840.113549.1.9.15'


OID = _OID.build_oid_enum()
