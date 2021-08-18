from samson.encoding.general import PKIAutoParser
from pyasn1.error import PyAsn1Error
from pyasn1.type.char import PrintableString, TeletexString
from samson.hashes.sha1 import SHA1
from samson.hashes.sha2 import SHA224, SHA256, SHA384, SHA512
from samson.hashes.md5 import MD5
from samson.hashes.md2 import MD2
from pyasn1_modules import rfc2459, rfc5280
from pyasn1.codec.der import encoder
from pyasn1.type.univ import Any, BitString, ObjectIdentifier, OctetString
from pyasn1.type.useful import UTCTime
from datetime import timezone

def invert_dict(dic):
    return {v:k for k,v in dic.items()}


# https://www.ietf.org/rfc/rfc5698.txt
HASH_OID_LOOKUP = {
    MD2: ObjectIdentifier('1.2.840.113549.2.2'),
    MD5: ObjectIdentifier('1.2.840.113549.2.5'),
    SHA1: ObjectIdentifier('1.3.14.3.2.26'),
    SHA224: ObjectIdentifier('2.16.840.1.101.3.4.2.4'),
    SHA256: ObjectIdentifier('2.16.840.1.101.3.4.2.1'),
    SHA384: ObjectIdentifier('2.16.840.1.101.3.4.2.2'),
    SHA512: ObjectIdentifier('2.16.840.1.101.3.4.2.3')
}

INVERSE_HASH_OID_LOOKUP = invert_dict(HASH_OID_LOOKUP)


# https://tools.ietf.org/html/rfc8017#appendix-A.2.4
SIGNING_ALG_OIDS = {
    'md2WithRSAEncryption': '1.2.840.113549.1.1.2',
    'md5WithRSAEncryption': '1.2.840.113549.1.1.4',
    'sha1WithRSAEncryption': '1.2.840.113549.1.1.5',
    'sha224WithRSAEncryption': '1.2.840.113549.1.1.14',
    'sha256WithRSAEncryption': '1.2.840.113549.1.1.11',
    'sha384WithRSAEncryption': '1.2.840.113549.1.1.12',
    'sha512WithRSAEncryption': '1.2.840.113549.1.1.13',
    'sha512-224WithRSAEncryption': '1.2.840.113549.1.1.15',
    'sha512-256WithRSAEncryption': '1.2.840.113549.1.1.16',
    'ecdsa-with-SHA1': '1.2.840.10045.4.1',
    'ecdsa-with-SHA224': '1.2.840.10045.4.3.1',
    'ecdsa-with-SHA256': '1.2.840.10045.4.3.2',
    'ecdsa-with-SHA384': '1.2.840.10045.4.3.3',
    'ecdsa-with-SHA512': '1.2.840.10045.4.3.4',
    'id-dsa-with-sha1': '1.2.840.10040.4.3',
    'id-dsa-with-sha224': '2.16.840.1.101.3.4.3.1',
    'id-dsa-with-sha256': '2.16.840.1.101.3.4.3.2'
}


INVERSE_SIGNING_ALG_OIDS = {v:k for k,v in SIGNING_ALG_OIDS.items()}


def parse_time(time_val):
    if 'utcTime' in time_val and time_val['utcTime'].hasValue():
        result = time_val['utcTime']
    else:
        result = time_val['generalTime']

    return result.asDateTime.astimezone(timezone.utc)


def build_time(dt):
    rev_time  = rfc5280.Time()
    rev_time['utcTime'] = UTCTime.fromDateTime(dt)
    return rev_time


def verify_signature(verification_key: 'EncodablePKI', algorithm_id: rfc2459.AlgorithmIdentifier, data: object, signature: BitString) -> bool:
    signature_alg = INVERSE_SIGNING_ALG_OIDS[str(algorithm_id['algorithm'])].replace('-', '_')
    alg           = verification_key.X509_SIGNING_ALGORITHMS[signature_alg].value
    signed_data   = encoder.encode(data)

    return alg.verify(verification_key, signed_data, signature)


def resolve_alg(algorithm_id: rfc2459.AlgorithmIdentifier) -> 'X509Signature':
    cert_sig_alg = INVERSE_SIGNING_ALG_OIDS[str(algorithm_id['algorithm'])].replace('-', '_')
    return PKIAutoParser.resolve_x509_signature_alg(cert_sig_alg).value


def build_signature_alg(signing_alg: 'X509Signature', signing_key: 'EncodablePKI') -> rfc2459.AlgorithmIdentifier:
    signature_alg = rfc2459.AlgorithmIdentifier()
    signature_alg['algorithm'] = SIGNING_ALG_OIDS[signing_alg.name]

    if hasattr(signing_key, 'X509_SIGNING_PARAMS'):
        signature_alg['parameters'] = Any(encoder.encode(signing_key.X509_SIGNING_PARAMS.encode(signing_key)))

    return signature_alg
