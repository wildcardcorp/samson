from samson.core.primitives import Hash
from samson.encoding.pem import PEMEncodable, pem_decode
from samson.encoding.asn1 import parse_time, resolve_alg, verify_signature, build_signature_alg
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag
from pyasn1.type.univ import ObjectIdentifier, Any
from pyasn1_modules import rfc2459
from pyasn1.error import PyAsn1Error
from pyasn1.type.useful import UTCTime
from samson.utilities.bytes import Bytes
from samson.encoding.x509.x509_extension import X509Extension, X509SubjectKeyIdentifier, X509BasicConstraints, X509SubjectAlternativeName
from samson.encoding.x509.x509_signature import X509Signature
from datetime import datetime
from samson.hashes.sha1 import SHA1
from samson.encoding.x509.x509_rdn import RDNSequence, CommonName

_ext_shorthand = {
    'is_ca': lambda is_ca: X509BasicConstraints(is_ca=is_ca),
    'sans': lambda names: X509SubjectAlternativeName(names=names)
}

_default_rdn = RDNSequence([CommonName(b'CA')])


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
        self, key: object, version: int=3, serial_number: int=0, issuer: RDNSequence=None, subject: RDNSequence=None, extensions: list=None,
        issuer_unique_id: int=None, subject_unique_id: int=None, not_before: datetime=None, not_after: datetime=None,
        signing_alg: X509Signature=None, signature_value: bytes=None, **kwargs
    ):
        self.key = key
        self.version = version
        self.serial_number = serial_number
        self.issuer = RDNSequence.wrap(issuer or _default_rdn)
        self.subject = RDNSequence.wrap(subject or _default_rdn)
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
        issuer.setComponentByPosition(0, self.issuer.build())

        # Subject RDN
        subject = rfc2459.Name()
        subject.setComponentByPosition(0, self.subject.build())

        signing_key = signing_key or self.key

        # Signature algorithm
        if not self.signing_alg and not hasattr(signing_key, "X509_SIGNING_DEFAULT"):
            raise ValueError("'signing_alg' not specified and 'signing_key' has no default algorithm")

        signing_alg   = self.signing_alg or signing_key.X509_SIGNING_DEFAULT.value
        signature_alg = build_signature_alg(signing_alg, signing_key)

        # Extensions
        extensions = rfc2459.Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))

        public_key_hash = SHA1().hash(Bytes(int(pub_info['subjectPublicKey'])))

        for extension in self.extensions:
            if type(extension) == X509SubjectKeyIdentifier and extension.key_identifier is None:
                extension = extension.copy()
                extension.key_identifier = public_key_hash

            extensions.append(extension.build())


        # Put together the TBSCert
        tbs_cert = rfc2459.TBSCertificate()
        tbs_cert['version']              = self.version-1
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
    

    def compute_ski(self, hash_obj: Hash=None):
        if not hash_obj:
            hash_obj = SHA1()

        pub_bytes = self.PUB_KEY_ENCODER.encode(self.key)
        return hash_obj.hash(Bytes(int(pub_bytes)))


    @classmethod
    def verify(cls, buffer: bytes, verification_key: object) -> bool:
        if buffer.strip().startswith(b'----'):
            buffer = pem_decode(buffer)

        # Decode the full cert and get the encoded TBSCertificate
        cert, _left_over = decoder.decode(buffer, asn1Spec=cls.SPEC)
        return verify_signature(verification_key, cert['signatureAlgorithm'], cert[cls.SIGNED_PART], cert[cls.SIG_KEY])


    @classmethod
    def decode(cls, buffer: bytes, **kwargs) -> object:
        cert, _left_over = decoder.decode(bytes(buffer), asn1Spec=rfc2459.Certificate())

        signature = Bytes(int(cert['signatureValue']))
        tbs_cert  = cert['tbsCertificate']
        version   = int(tbs_cert['version'])

        serial_num        = int(tbs_cert['serialNumber'])
        issuer_unique_id  = int(tbs_cert['issuerUniqueID']) if tbs_cert['issuerUniqueID'].hasValue() else None
        subject_unique_id = int(tbs_cert['subjectUniqueID']) if tbs_cert['subjectUniqueID'].hasValue() else None

        # Decode RDNs
        issuer  = RDNSequence.parse(tbs_cert['issuer'][0])
        subject = RDNSequence.parse(tbs_cert['subject'][0])

        # TODO: What to do with 'sig_params'? Is it needed?
        if tbs_cert['signature']['parameters'].hasValue():
            sig_params = bytes(tbs_cert['signature']['parameters'])
        else:
            sig_params = None

        validity = tbs_cert['validity']

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
        signing_alg = resolve_alg(cert['signatureAlgorithm'])

        return cls(
            key=key, version=version+1, serial_number=serial_num, issuer=issuer, subject=subject,
            issuer_unique_id=issuer_unique_id, subject_unique_id=subject_unique_id, not_before=not_before, not_after=not_after,
            signing_key=None, signing_alg=signing_alg, signature_value=signature, extensions=extensions
        )


    def get_extension(self, ext_type: type):
        return [e for e in self.extensions if type(e) is ext_type][0]


    @staticmethod
    def clone(usr_data, iss_data):
        from samson.encoding.general import PKIAutoParser
        from samson.public_key.rsa import RSA
        import logging

        logger = logging.getLogger(__name__)
    
        logger.info('Importing keys')
        iss  = PKIAutoParser.import_key(iss_data)
        usr  = PKIAutoParser.import_key(usr_data)

        assert type(iss.key) is RSA

        signer    = usr.signing_alg._build_signer(iss.key)
        sig_hash  = usr.signing_alg.parse_signature(iss.key, usr.signature_value)
        plaintext = signer._build_sigdata(sig_hash)

        logger.info('Duplicating signature')
        plaintext = Bytes(iss.key.encrypt(usr.signature_value))
        dup_key   = RSA.duplicate_ciphertext_key_selection(iss.key.n, usr.signature_value, plaintext)


        assert Bytes(dup_key.encrypt(usr.signature_value.int())) == plaintext

        logger.info('Building clone cert')
        iss_dup = iss.deepcopy()
        iss_dup.key = dup_key
        iss_dup.signature_value = None
        encoded = iss_dup.encode()

        logging.info('Verifying all signatures')
        iss_signed = PKIAutoParser.import_key(encoded)
        assert iss_signed.verify(encoded, iss_signed.key)

        assert usr.verify(usr_data, iss_signed.key)

        return iss_signed
