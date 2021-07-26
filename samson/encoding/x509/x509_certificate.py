from samson.encoding.pem import PEMEncodable, pem_decode
from samson.encoding.asn1 import parse_rdn,rdn_to_str
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag
from pyasn1.type.univ import ObjectIdentifier, Any
from pyasn1_modules import rfc2459
from pyasn1.error import PyAsn1Error
from pyasn1.type.useful import UTCTime
from samson.utilities.bytes import Bytes
from samson.encoding.asn1 import SIGNING_ALG_OIDS, INVERSE_SIGNING_ALG_OIDS
from samson.encoding.x509.x509_extension import X509Extension, X509SubjectKeyIdentifier, X509BasicConstraints, X509SubjectAlternativeName
from datetime import datetime, timezone
from samson.hashes.sha1 import SHA1

_ext_shorthand = {
    'is_ca': lambda is_ca: X509BasicConstraints(is_ca=is_ca),
    'sans': lambda names: X509SubjectAlternativeName(names=names)
}


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
        self, key: object, version: int=2, serial_number: int=0, issuer: str='CN=ca', subject: str='CN=ca', extensions: list=None,
        issuer_unique_id: int=None, subject_unique_id: int=None, not_before: datetime=None, not_after: datetime=None,
        signing_alg: object=None, signature_value: bytes=None, **kwargs
    ):
        self.key = key
        self.version = version
        self.serial_number = serial_number
        self.issuer = issuer
        self.subject = subject
        self.extensions = extensions or []

        for k,v in kwargs.items():
            if k in _ext_shorthand:
                self.extensions.append(_ext_shorthand[k](v))

        self.issuer_unique_id = issuer_unique_id
        self.subject_unique_id = subject_unique_id
        self.not_before = not_before or datetime.now()
        self.not_after = not_after or self.not_before.replace(year=self.not_before.year + 1)
        self.signing_alg = signing_alg
        self.signature_value = signature_value


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

        if hasattr(signing_key, 'X509_SIGNING_PARAMS'):
            signature_alg['parameters'] = Any(encoder.encode(signing_key.X509_SIGNING_PARAMS.encode(signing_key)))


        # Extensions
        extensions = rfc2459.Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))

        public_key_hash = SHA1().hash(Bytes(int(pub_info['subjectPublicKey'])))

        for extension in self.extensions:
            if type(extension) == X509SubjectKeyIdentifier and extension.key_identifier is None:
                extension = extension.copy()
                extension.key_identifier = public_key_hash

            extensions.append(extension.build_extension())


        # Put together the TBSCert
        tbs_cert = rfc2459.TBSCertificate()
        tbs_cert['version']              = self.version
        tbs_cert['serialNumber']         = serial_num
        tbs_cert['signature']            = signature_alg
        tbs_cert['issuer']               = issuer
        tbs_cert['validity']             = validity
        tbs_cert['subject']              = subject
        tbs_cert['subjectPublicKeyInfo'] = pub_info

        if self.issuer_unique_id is not None:
            tbs_cert['issuerUniqueID'] = self.issuer_unique_id

        if self.subject_unique_id is not None:
            tbs_cert['subjectUniqueID'] = self.subject_unique_id


        if len(extensions):
            tbs_cert['extensions'] = extensions


        # Inject or compute the TBSCert signature
        if self.signature_value is not None:
            sig_value = Bytes.wrap(self.signature_value).int()
        else:
            encoded_tbs = encoder.encode(tbs_cert)
            sig_value   = signing_alg.sign(signing_key, encoded_tbs)


        # Build the Cert object
        cert = rfc2459.Certificate()
        cert['tbsCertificate']     = tbs_cert
        cert['signatureAlgorithm'] = signature_alg
        cert['signatureValue']     = sig_value

        encoded = encoder.encode(cert)
        return X509Certificate.transport_encode(encoded, **kwargs)


    @classmethod
    def verify(cls, buffer: bytes, verification_key: object) -> bool:
        if buffer.strip().startswith(b'----'):
            buffer = pem_decode(buffer)

        # Decode the full cert and get the encoded TBSCertificate
        cert, _left_over = decoder.decode(buffer, asn1Spec=cls.SPEC)

        sig_value     = cert[cls.SIG_KEY]
        signature_alg = INVERSE_SIGNING_ALG_OIDS[str(cert['signatureAlgorithm']['algorithm'])].replace('-', '_')
        tbs_cert      = cert[cls.SIGNED_PART]
        encoded_tbs   = encoder.encode(tbs_cert)

        alg = verification_key.X509_SIGNING_ALGORITHMS[signature_alg].value
        return alg.verify(verification_key, encoded_tbs, sig_value)


    @classmethod
    def decode(cls, buffer: bytes, **kwargs) -> object:
        from samson.encoding.general import PKIAutoParser

        cert, _left_over = decoder.decode(bytes(buffer), asn1Spec=rfc2459.Certificate())

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

        validity = tbs_cert['validity']

        def parse_time(time_val):
            if 'utcTime' in time_val and time_val['utcTime'].hasValue():
                result = time_val['utcTime']
            else:
                result = time_val['generalTime']

            return result.asDateTime.astimezone(timezone.utc)


        not_before = parse_time(validity['notBefore'])
        not_after  = parse_time(validity['notAfter'])


        #is_ca = False
        extensions = []
        if 'extensions' in tbs_cert:
            for ext in tbs_cert['extensions']:
                try:
                    extensions.append(X509Extension.parse(ext))
                except ValueError:
                    pass


        buffer      = encoder.encode(tbs_cert['subjectPublicKeyInfo'])
        key         = cls.PUB_KEY_DECODER.decode(buffer).key
        signing_alg = PKIAutoParser.resolve_x509_signature_alg(cert_sig_alg.replace('-', '_')).value

        return cls(
            key=key, version=version, serial_number=serial_num, issuer=issuer, subject=subject,
            issuer_unique_id=issuer_unique_id, subject_unique_id=subject_unique_id, not_before=not_before, not_after=not_after,
            signing_key=None, signing_alg=signing_alg, signature_value=signature, extensions=extensions
        )
