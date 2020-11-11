from samson.encoding.pem import PEMEncodable, pem_decode
from samson.encoding.asn1 import parse_rdn,rdn_to_str
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag
from pyasn1.type.univ import ObjectIdentifier, Any, OctetString
from pyasn1_modules import rfc2459
from pyasn1.error import PyAsn1Error
from pyasn1.type.useful import UTCTime
from samson.utilities.bytes import Bytes
from samson.hashes.sha1 import SHA1
from samson.encoding.asn1 import SIGNING_ALG_OIDS, INVERSE_SIGNING_ALG_OIDS
from datetime import datetime


class X509Certificate(PEMEncodable):
    ALG_OID = None
    PARAM_ENCODER = None
    PUB_KEY_ENCODER = None
    PUB_KEY_DECODER = None

    DEFAULT_MARKER = 'CERTIFICATE'
    DEFAULT_PEM = True
    USE_RFC_4716 = False

    SPEC = rfc2459.Certificate()
    SIGNED_SPEC = rfc2459.TBSCertificate()
    SIGNED_PART = 'tbsCertificate'
    SIG_KEY     = 'signatureValue'
    PK_INFO_KEY = 'subjectPublicKeyInfo'

    def __init__(
        self, key: object, version: int=2, serial_number: int=0, issuer: str='CN=ca', subject: str='CN=ca',
        issuer_unique_id: int=None, subject_unique_id: int=None, not_before: datetime=None, not_after: datetime=None,
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


    @classmethod
    def check(cls, buffer: bytes, **kwargs) -> bool:
        try:
            cert, _ = decoder.decode(buffer, asn1Spec=cls.SPEC)
            return str(cert[cls.SIGNED_PART][cls.PK_INFO_KEY]['algorithm']['algorithm']) == cls.ALG_OID
        except (PyAsn1Error, KeyError):
            return False


    def encode(self, signing_key: 'EncodablePKI'=None, **kwargs) -> bytes:
        """
        Parameters:
            signing_key (EncodablePKI): Key to sign the cert with.
        """ \
        + PEMEncodable.DOC_PARAMS + \
        """

        Returns:
            X509Certificate: Certifcate.
        """
        # Algorithm ID
        alg_oid = self.ALG_OID if type(self.ALG_OID) is str else self.ALG_OID(self.key)

        alg_id = rfc2459.AlgorithmIdentifier()
        alg_id['algorithm']  = ObjectIdentifier(alg_oid)

        if self.PARAM_ENCODER:
            alg_id['parameters'] = Any(encoder.encode(self.PARAM_ENCODER.encode(self.key)))


        # Serial number
        serial_num = rfc2459.CertificateSerialNumber(self.serial_number)

        # Validity (time valid)
        validity = rfc2459.Validity()
        validity['notBefore'] = rfc2459.Time()
        validity['notBefore']['utcTime'] = UTCTime.fromDateTime(self.not_before)

        validity['notAfter']  = rfc2459.Time()
        validity['notAfter']['utcTime'] = UTCTime.fromDateTime(self.not_after)


        # Public key serialization
        pub_info = rfc2459.SubjectPublicKeyInfo()
        pub_info['algorithm']        = alg_id
        pub_info['subjectPublicKey'] = self.PUB_KEY_ENCODER.encode(self.key)

        # Issuer RDN
        issuer = rfc2459.Name()
        issuer.setComponentByPosition(0, parse_rdn(self.issuer))

        # Subject RDN
        subject = rfc2459.Name()
        subject.setComponentByPosition(0, parse_rdn(self.subject))

        signing_key = signing_key or self.key

        # Signature algorithm
        if not self.signing_alg and not hasattr(signing_key, "X509_SIGNING_DEFAULT"):
            raise ValueError("'signing_alg' not specified and 'signing_key' has no default algorithm")

        signing_alg = self.signing_alg or signing_key.X509_SIGNING_DEFAULT.value


        signature_alg = rfc2459.AlgorithmIdentifier()
        signature_alg['algorithm'] = SIGNING_ALG_OIDS[signing_alg.name]

        if self.PARAM_ENCODER:
            signature_alg['parameters'] = Any(encoder.encode(self.PARAM_ENCODER.encode(self.key)))


        # Extensions
        extensions = rfc2459.Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))

        if self.is_ca:
            # SKI
            pkey_bytes = Bytes(int(pub_info['subjectPublicKey']))

            ski_ext = rfc2459.Extension()
            ski_ext['extnID']    = ObjectIdentifier([2, 5, 29, 14])
            ski_ext['extnValue'] = OctetString(encoder.encode(rfc2459.SubjectKeyIdentifier(SHA1().hash(pkey_bytes))))

            # CA basic constraint
            ca_value = rfc2459.BasicConstraints()
            ca_value.setComponentByName('cA', True)

            ca_ext = rfc2459.Extension()
            ca_ext.setComponentByName('extnID', '2.5.29.19')
            ca_ext.setComponentByName('critical', True)
            ca_ext.setComponentByName('extnValue', OctetString(encoder.encode(ca_value)))

            extensions.setComponentByPosition(0, ski_ext)
            extensions.setComponentByPosition(1, ca_ext)


        # Put together the TBSCert
        tbs_cert = rfc2459.TBSCertificate()
        tbs_cert['version']              = self.version
        tbs_cert['serialNumber']         = serial_num
        tbs_cert['signature']            = signature_alg
        tbs_cert['issuer']               = issuer
        tbs_cert['validity']             = validity
        tbs_cert['subject']              = subject
        tbs_cert['subjectPublicKeyInfo'] = pub_info

        # TODO: pyasn1 doesn't see these as optional
        # This means samson encodes certs wrong that don't include
        # these values
        tbs_cert['issuerUniqueID']  = self.issuer_unique_id or 0
        tbs_cert['subjectUniqueID'] = self.subject_unique_id or 0


        if len(extensions):
            tbs_cert['extensions'] = extensions


        # Inject or compute the TBSCert signature
        if self.signature_value is not None:
            sig_value = Bytes.wrap(self.signature_value).int()
        else:
            encoded_tbs = encoder.encode(tbs_cert, asn1Spec=self.SIGNED_SPEC)
            sig_value   = signing_alg.sign(signing_key, encoded_tbs)


        # Build the Cert object
        cert = rfc2459.Certificate()
        cert['tbsCertificate']     = tbs_cert
        cert['signatureAlgorithm'] = signature_alg
        cert['signatureValue']     = sig_value

        encoded = encoder.encode(cert, asn1Spec=self.SPEC)
        return X509Certificate.transport_encode(encoded, **kwargs)


    @classmethod
    def verify(cls, buffer: bytes, verification_key: object) -> bool:
        if buffer.startswith(b'----'):
            buffer = pem_decode(buffer)

        # Decode the full cert and get the encoded TBSCertificate
        cert, _left_over = decoder.decode(buffer, asn1Spec=cls.SPEC)

        sig_value     = cert[cls.SIG_KEY]
        signature_alg = INVERSE_SIGNING_ALG_OIDS[str(cert['signatureAlgorithm']['algorithm'])].replace('-', '_')
        tbs_cert      = cert[cls.SIGNED_PART]
        encoded_tbs   = encoder.encode(tbs_cert, asn1Spec=cls.SIGNED_SPEC)

        alg = verification_key.X509_SIGNING_ALGORITHMS[signature_alg].value
        return alg.verify(verification_key, encoded_tbs, sig_value)


    @classmethod
    def decode(cls, buffer: bytes, **kwargs) -> object:
        from samson.encoding.general import PKIAutoParser

        cert, _left_over = decoder.decode(buffer, asn1Spec=rfc2459.Certificate())

        signature    = Bytes(int(cert['signatureValue']))
        cert_sig_alg = INVERSE_SIGNING_ALG_OIDS[str(cert['signatureAlgorithm']['algorithm'])]

        tbs_cert = cert['tbsCertificate']
        version  = int(tbs_cert['version'])

        serial_num        = int(tbs_cert['serialNumber'])
        issuer_unique_id  = int(tbs_cert['issuerUniqueID']) if tbs_cert['issuerUniqueID'].hasValue() else None
        subject_unique_id = int(tbs_cert['subjectUniqueID']) if tbs_cert['subjectUniqueID'].hasValue() else None

        # Decode RDNs
        issuer  = rdn_to_str(tbs_cert['issuer'][0])
        subject = rdn_to_str(tbs_cert['subject'][0])

        # TODO: What to do with 'sig_params'? Is it needed?
        if tbs_cert['signature']['parameters'].hasValue():
            sig_params = bytes(tbs_cert['signature']['parameters'])
        else:
            sig_params = None

        validity   = tbs_cert['validity']
        not_before = validity['notBefore']['utcTime'].asDateTime
        not_after  = validity['notAfter']['utcTime'].asDateTime

        is_ca = False
        if 'extensions' in tbs_cert:
            for ext in tbs_cert['extensions']:
                if str(ext['extnID']) == '2.5.29.19':
                    ext_val, _ = decoder.decode(bytes(ext['extnValue']))
                    if len(ext_val):
                        is_ca = bool(ext_val[0])
                    break


        buffer      = encoder.encode(tbs_cert['subjectPublicKeyInfo'])
        key         = cls.PUB_KEY_DECODER.decode(buffer).key
        signing_alg = PKIAutoParser.resolve_x509_signature_alg(cert_sig_alg.replace('-', '_')).value

        return cls(
            key=key, version=version, serial_number=serial_num, issuer=issuer, subject=subject,
            issuer_unique_id=issuer_unique_id, subject_unique_id=subject_unique_id, not_before=not_before, not_after=not_after,
            signing_key=None, signing_alg=signing_alg, is_ca=is_ca, signature_value=signature
        )
