from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import ObjectIdentifier, BitString, Any
from pyasn1_modules import rfc2459
from pyasn1.error import PyAsn1Error
from pyasn1.type.useful import UTCTime
from datetime import datetime

class X509Certificate(object):
    ALG_OID = None
    PARAM_ENCODER = None
    PUB_KEY_ENCODER = None
    PUB_KEY_DECODER = None


    @classmethod
    def check(cls, buffer: bytes):
        try:
            cert, _ = decoder.decode(buffer, asn1Spec=rfc2459.Certificate())
            return str(cert['tbsCertificate']['subjectPublicKeyInfo']['algorithm']['algorithm']) == cls.ALG_OID
        except PyAsn1Error as _:
            return False


    @classmethod
    def encode(cls, pki_key: object):
        alg_oid = cls.ALG_OID if type(cls.ALG_OID) is str else cls.ALG_OID(pki_key)

        alg_id = rfc2459.AlgorithmIdentifier()
        alg_id['algorithm']  = ObjectIdentifier([int(item) for item in alg_oid.split('.')])

        if cls.PARAM_ENCODER:
            alg_id['parameters'] = Any(encoder.encode(cls.PARAM_ENCODER.encode(pki_key)))

        serial_num = rfc2459.CertificateSerialNumber(0)

        dt = datetime.now()

        validity = rfc2459.Validity()
        validity['notBefore'] = rfc2459.Time()
        validity['notBefore']['utcTime'] = UTCTime.fromDateTime(dt)

        validity['notAfter']  = rfc2459.Time()
        validity['notAfter']['utcTime'] = UTCTime.fromDateTime(dt.replace(year=dt.year + 1))

        pub_info = rfc2459.SubjectPublicKeyInfo()
        pub_info['algorithm']        = alg_id
        pub_info['subjectPublicKey'] = cls.PUB_KEY_ENCODER.encode(pki_key)

        issuer = rfc2459.Name()
        issuer.setComponentByPosition(0, rfc2459.RDNSequence())

        tbs_cert = rfc2459.TBSCertificate()
        tbs_cert['version']              = 2
        tbs_cert['serialNumber']         = serial_num
        tbs_cert['signature']            = alg_id
        tbs_cert['issuer']               = issuer
        tbs_cert['validity']             = validity
        tbs_cert['subject']              = issuer
        tbs_cert['subjectPublicKeyInfo'] = pub_info
        tbs_cert['issuerUniqueID']       = 10
        tbs_cert['subjectUniqueID']      = 11

        cert = rfc2459.Certificate()
        cert['tbsCertificate']     = tbs_cert
        cert['signatureAlgorithm'] = alg_id
        cert['signatureValue']     = BitString(1)

        return encoder.encode(cert, asn1Spec=rfc2459.Certificate())



    @classmethod
    def decode(cls, buffer: bytes):
        cert, _left_over = decoder.decode(buffer, asn1Spec=rfc2459.Certificate())
        buffer = encoder.encode(cert['tbsCertificate']['subjectPublicKeyInfo'])
        return cls.PUB_KEY_DECODER.decode(buffer)
