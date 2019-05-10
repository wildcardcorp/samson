from samson.encoding.pem import PEMEncodable, pem_decode
from samson.encoding.asn1 import parse_rdn
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


    @classmethod
    def check(cls, buffer: bytes, **kwargs):
        try:
            cert, _ = decoder.decode(buffer, asn1Spec=rfc2459.Certificate())
            return str(cert['tbsCertificate']['subjectPublicKeyInfo']['algorithm']['algorithm']) == cls.ALG_OID
        except PyAsn1Error as _:
            return False


    @classmethod
    def encode(cls, pki_key: object, **kwargs):
        # Algorithm ID
        alg_oid = cls.ALG_OID if type(cls.ALG_OID) is str else cls.ALG_OID(pki_key)

        alg_id = rfc2459.AlgorithmIdentifier()
        alg_id['algorithm']  = ObjectIdentifier(alg_oid)

        if cls.PARAM_ENCODER:
            alg_id['parameters'] = Any(encoder.encode(cls.PARAM_ENCODER.encode(pki_key)))


        # Serial number
        serial_num = rfc2459.CertificateSerialNumber(kwargs.get('serial_number') or 0)


        # Validity (time valid)
        not_before = kwargs.get('not_before') or datetime.now()
        not_after = kwargs.get('not_after') or not_before.replace(year=not_before.year + 1)

        validity = rfc2459.Validity()
        validity['notBefore'] = rfc2459.Time()
        validity['notBefore']['utcTime'] = UTCTime.fromDateTime(not_before)

        validity['notAfter']  = rfc2459.Time()
        validity['notAfter']['utcTime'] = UTCTime.fromDateTime(not_after)


        # Public key serialization
        pub_info = rfc2459.SubjectPublicKeyInfo()
        pub_info['algorithm']        = alg_id
        pub_info['subjectPublicKey'] = cls.PUB_KEY_ENCODER.encode(pki_key)

        # Issuer RDN
        issuer = rfc2459.Name()
        issuer.setComponentByPosition(0, parse_rdn(kwargs.get('issuer') or 'CN=ca'))

        # Subject RDN
        subject = rfc2459.Name()
        subject.setComponentByPosition(0, parse_rdn(kwargs.get('subject') or 'CN=ca'))

        # Signature algorithm
        signing_key = kwargs.get('signing_key') or pki_key
        signing_alg = (kwargs.get('signing_alg') or signing_key.X509_SIGNING_DEFAULT).value

        signature_alg = rfc2459.AlgorithmIdentifier()
        signature_alg['algorithm'] = SIGNING_ALG_OIDS[signing_alg.name]

        if cls.PARAM_ENCODER:
            signature_alg['parameters'] = Any(encoder.encode(cls.PARAM_ENCODER.encode(pki_key)))


        # Extensions
        extensions = rfc2459.Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))

        if kwargs.get('ca') and kwargs.get('ca') == True:
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
        tbs_cert['version']              = 2
        tbs_cert['serialNumber']         = serial_num
        tbs_cert['signature']            = signature_alg
        tbs_cert['issuer']               = issuer
        tbs_cert['validity']             = validity
        tbs_cert['subject']              = subject
        tbs_cert['subjectPublicKeyInfo'] = pub_info
        tbs_cert['issuerUniqueID']       = kwargs.get('issuer_unique_id') or 10
        tbs_cert['subjectUniqueID']      = kwargs.get('subject_unique_id') or 11

        if len(extensions):
            tbs_cert['extensions'] = extensions


        # Inject or compute the TBSCert signature
        if kwargs.get('signature_value') is not None:
            sig_value = Bytes.wrap(kwargs.get('signature_value')).int()
        else:
            encoded_tbs = encoder.encode(tbs_cert, asn1Spec=rfc2459.TBSCertificate())
            sig_value   = signing_alg.sign(signing_key, encoded_tbs)


        # Build the Cert object
        cert = rfc2459.Certificate()
        cert['tbsCertificate']     = tbs_cert
        cert['signatureAlgorithm'] = signature_alg
        cert['signatureValue']     = sig_value

        encoded = encoder.encode(cert, asn1Spec=rfc2459.Certificate())
        return X509Certificate.transport_encode(encoded, **kwargs)


    @staticmethod
    def verify(buffer: bytes, verification_key: object) -> bool:
        if buffer.startswith(b'----'):
            buffer = pem_decode(buffer)

        # Decode the full cert and get the encoded TBSCertificate
        cert, _left_over = decoder.decode(buffer, asn1Spec=rfc2459.Certificate())

        sig_value     = cert['signatureValue']
        signature_alg = INVERSE_SIGNING_ALG_OIDS[str(cert['signatureAlgorithm']['algorithm'])].replace('-', '_')
        tbs_cert      = cert['tbsCertificate']
        encoded_tbs   = encoder.encode(tbs_cert, asn1Spec=rfc2459.TBSCertificate())

        alg = verification_key.X509_SIGNING_ALGORITHMS[signature_alg].value
        return alg.verify(verification_key, encoded_tbs, sig_value)



    @classmethod
    def decode(cls, buffer: bytes, **kwargs):
        cert, _left_over = decoder.decode(buffer, asn1Spec=rfc2459.Certificate())
        buffer = encoder.encode(cert['tbsCertificate']['subjectPublicKeyInfo'])
        return cls.PUB_KEY_DECODER.decode(buffer)
