from samson.encoding.pem import PEMEncodable
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import ObjectIdentifier, BitString, Any
from pyasn1_modules import rfc2459, rfc3447
from pyasn1.error import PyAsn1Error
from pyasn1.type.useful import UTCTime
from samson.utilities.bytes import Bytes
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
        alg_id['algorithm']  = ObjectIdentifier([int(item) for item in alg_oid.split('.')])

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
        issuer.setComponentByPosition(0, rfc2459.RDNSequence())


        # Put together the TBSCert
        tbs_cert = rfc2459.TBSCertificate()
        tbs_cert['version']              = 2
        tbs_cert['serialNumber']         = serial_num
        tbs_cert['signature']            = rfc3447.sha1WithRSAEncryption
        tbs_cert['issuer']               = issuer
        tbs_cert['validity']             = validity
        tbs_cert['subject']              = issuer
        tbs_cert['subjectPublicKeyInfo'] = pub_info
        tbs_cert['issuerUniqueID']       = kwargs.get('issuer_unique_id') or 10
        tbs_cert['subjectUniqueID']      = kwargs.get('subject_unique_id') or 11


        # Compute or inject the TBSCert signature
        if kwargs.get('signature_value'):
            sig_value = Bytes.wrap(kwargs.get('signature_value')).int()
        else:
            from samson.hashes.sha1 import SHA1
            # TODO: Sign the cert
            #signing_key = kwargs.get('signing_key') or pki_key
            sig_value = encoder.encode(tbs_cert, asn1Spec=rfc2459.TBSCertificate())
            sig_value = SHA1().hash(sig_value)
            sig_value = Bytes(pki_key.encrypt(sig_value))


        # Build the Cert object
        cert = rfc2459.Certificate()
        cert['tbsCertificate']     = tbs_cert
        cert['signatureAlgorithm'] = alg_id
        cert['signatureValue']     = BitString(sig_value)

        encoded = encoder.encode(cert, asn1Spec=rfc2459.Certificate())
        return X509Certificate.transport_encode(encoded, **kwargs)



    @classmethod
    def decode(cls, buffer: bytes, **kwargs):
        cert, _left_over = decoder.decode(buffer, asn1Spec=rfc2459.Certificate())
        buffer = encoder.encode(cert['tbsCertificate']['subjectPublicKeyInfo'])
        return cls.PUB_KEY_DECODER.decode(buffer)
