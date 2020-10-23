from samson.encoding.pem import PEMEncodable, pem_decode
from samson.encoding.x509.x509_certificate import X509Certificate
from samson.encoding.asn1 import parse_rdn,rdn_to_str
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag
from pyasn1.type.univ import ObjectIdentifier, Any, OctetString
from pyasn1_modules import rfc2459, rfc2986, rfc5280
from pyasn1.error import PyAsn1Error
from pyasn1.type.useful import UTCTime
from samson.utilities.bytes import Bytes
from samson.hashes.sha1 import SHA1
from samson.encoding.asn1 import SIGNING_ALG_OIDS, INVERSE_SIGNING_ALG_OIDS
from datetime import datetime


class X509CertificateSigningRequest(X509Certificate):
    DEFAULT_MARKER = 'CERTIFICATE REQUEST'
    SPEC           = rfc2986.CertificationRequest()
    SIGNED_SPEC    = rfc2986.CertificationRequestInfo()
    SIGNED_PART    = 'certificationRequestInfo'
    SIG_KEY        = 'signature'


    def __init__(
        self, key: object, version: int=2, serial_number: int=0, issuer: str='CN=ca', subject: str='CN=ca',
        issuer_unique_id: int=10, subject_unique_id: int=11, not_before: datetime=None, not_after: datetime=None,
        signing_alg: object=None, is_ca: bool=False, signature_value: bytes=None, **kwargs
    ):
        self.key = key
        self.version = version
        self.serial_number = serial_number
        self.issuer = issuer
        self.subject = subject
        self.issuer_unique_id = issuer_unique_id
        self.subject_unique_id = subject_unique_id
        self.not_before = not_before or datetime.now()
        self.not_after = not_after or self.not_before.replace(year=self.not_before.year + 1)
        self.signing_alg = signing_alg
        self.signature_value = signature_value
        self.is_ca = is_ca



    def encode(self, signing_key: 'EncodablePKI'=None, **kwargs) -> bytes:
        info = rfc2986.CertificationRequestInfo()
        info['version'] = 0

        # Subject RDN
        subject = rfc5280.Name()
        subject.setComponentByPosition(0, parse_rdn(self.subject))

        info['subject'] = subject


        # Algorithm ID
        alg_oid = self.ALG_OID if type(self.ALG_OID) is str else self.ALG_OID(self.key)

        alg_id = rfc5280.AlgorithmIdentifier()
        alg_id['algorithm']  = ObjectIdentifier(alg_oid)

        if self.PARAM_ENCODER:
            alg_id['parameters'] = Any(encoder.encode(self.PARAM_ENCODER.encode(self.key)))


        # Public key serialization
        pub_info = rfc5280.SubjectPublicKeyInfo()
        pub_info['algorithm']        = alg_id
        pub_info['subjectPublicKey'] = self.PUB_KEY_ENCODER.encode(self.key)

        info['subjectPKInfo'] = pub_info


        # Signature algorithm
        signing_key = signing_key or self.key

        if not self.signing_alg and not hasattr(signing_key, "X509_SIGNING_DEFAULT"):
            raise ValueError("'signing_alg' not specified and 'signing_key' has no default algorithm")

        signing_alg = self.signing_alg or signing_key.X509_SIGNING_DEFAULT.value


        signature_alg = rfc5280.AlgorithmIdentifier()
        signature_alg['algorithm'] = SIGNING_ALG_OIDS[signing_alg.name]

        if self.PARAM_ENCODER:
            signature_alg['parameters'] = Any(encoder.encode(self.PARAM_ENCODER.encode(self.key)))


        # Inject or compute the CRI signature
        if self.signature_value is not None:
            sig_value = Bytes.wrap(self.signature_value).int()
        else:
            encoded_cri = encoder.encode(info, asn1Spec=rfc2986.CertificationRequestInfo())
            sig_value   = signing_alg.sign(signing_key, encoded_cri)


        csr = rfc2986.CertificationRequest()
        csr['certificationRequestInfo'] = info
        csr['signatureAlgorithm']       = signature_alg
        csr['signature']                = sig_value

        encoded = encoder.encode(csr, asn1Spec=rfc2986.CertificationRequest())
        return X509CertificateSigningRequest.transport_encode(encoded, **kwargs)
