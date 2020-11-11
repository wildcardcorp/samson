from samson.encoding.x509.x509_certificate import X509Certificate
from samson.encoding.asn1 import parse_rdn,rdn_to_str
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import ObjectIdentifier, Any
from pyasn1_modules import rfc2986, rfc5280
from samson.utilities.bytes import Bytes
from samson.encoding.asn1 import SIGNING_ALG_OIDS, INVERSE_SIGNING_ALG_OIDS


class X509CertificateSigningRequest(X509Certificate):
    DEFAULT_MARKER = 'CERTIFICATE REQUEST'
    SPEC           = rfc2986.CertificationRequest()
    SIGNED_SPEC    = rfc2986.CertificationRequestInfo()
    SIGNED_PART    = 'certificationRequestInfo'
    SIG_KEY        = 'signature'
    PK_INFO_KEY    = 'subjectPKInfo'


    def __init__(
        self, key: object, version: int=0, subject: str='CN=ca',
        signing_alg: object=None, signature_value: bytes=None, **kwargs
    ):
        self.key = key
        self.version = version
        self.subject = subject
        self.signing_alg = signing_alg
        self.signature_value = signature_value



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


    @classmethod
    def decode(cls, buffer: bytes, **kwargs) -> object:
        from samson.encoding.general import PKIAutoParser

        csr, _left_over = decoder.decode(buffer, asn1Spec=rfc2986.CertificationRequest())
        signature       = Bytes(int(csr['signature']))

        info    = csr['certificationRequestInfo']
        version = int(info['version'])

        # Decode RDNs
        subject = rdn_to_str(info['subject'][0])

        cert_sig_alg = INVERSE_SIGNING_ALG_OIDS[str(csr['signatureAlgorithm']['algorithm'])]

        buffer      = encoder.encode(info['subjectPKInfo'])
        key         = cls.PUB_KEY_DECODER.decode(buffer).key
        signing_alg = PKIAutoParser.resolve_x509_signature_alg(cert_sig_alg.replace('-', '_')).value

        return cls(key=key, version=version, subject=subject, signing_alg=signing_alg, signature_value=signature)
