from samson.utilities.bytes import Bytes
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import Integer, ObjectIdentifier, BitString, SequenceOf, Sequence, Null, OctetString, Any
from pyasn1_modules import rfc2459
from pyasn1.error import PyAsn1Error
from pyasn1.type.useful import UTCTime
from datetime import datetime
import math


class X509Certificate(object):
    ALG_OID = None
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
    def encode(cls, rsa_key: object):
        alg_id = rfc2459.AlgorithmIdentifier()
        alg_id['algorithm']  = ObjectIdentifier([int(item) for item in cls.ALG_OID.split('.')])
        alg_id['parameters'] = Any(b'\x05\x00')

        serial_num = rfc2459.CertificateSerialNumber(0)

        dt = datetime.now()

        validity = rfc2459.Validity()
        validity['notBefore'] = rfc2459.Time()
        validity['notBefore']['utcTime'] = UTCTime.fromDateTime(dt)

        validity['notAfter']  = rfc2459.Time()
        validity['notAfter']['utcTime'] = UTCTime.fromDateTime(dt.replace(year=dt.year + 1))

        pub_info = rfc2459.SubjectPublicKeyInfo()
        pub_info['algorithm']        = alg_id
        pub_info['subjectPublicKey'] = cls.PUB_KEY_ENCODER.encode(rsa_key)

        issuer = rfc2459.Name()
        issuer.setComponentByPosition(0, rfc2459.RDNSequence())
        # issuer[0].setComponentByPosition(0, rfc2459.RelativeDistinguishedName())
        # issuer[0][0].setComponentByPosition(0, rfc2459.AttributeTypeAndValue())
        # issuer[0][0][0].setComponentByPosition(0, rfc2459.AttributeType(ObjectIdentifier([2, 5, 4, 6])))
        # issuer[0][0][0].setComponentByPosition(1, rfc2459.AttributeValue(OctetString(0x13025553)))
        # issuer[0][0][0][0] = '2.5.4.6'
        # issuer[0][0][0][1] = 0x13025553

        #return encoder.encode(issuer, asn1Spec=rfc2459.Name())


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
        buffer = Bytes(int(cert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey']))
        return cls.PUB_KEY_DECODER.decode(buffer)
