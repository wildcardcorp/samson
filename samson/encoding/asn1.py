from samson.hashes.sha1 import SHA1
from samson.hashes.sha2 import SHA224, SHA256, SHA384, SHA512
from pyasn1_modules import rfc2459
from pyasn1.codec.der import encoder
from pyasn1.type.univ import ObjectIdentifier, OctetString

# https://www.ietf.org/rfc/rfc5698.txt
HASH_OID_LOOKUP = {
    SHA1: ObjectIdentifier('1.3.14.3.2.26'),
    SHA224: ObjectIdentifier('2.16.840.1.101.3.4.2.4'),
    SHA256: ObjectIdentifier('2.16.840.1.101.3.4.2.1'),
    SHA384: ObjectIdentifier('2.16.840.1.101.3.4.2.2'),
    SHA512: ObjectIdentifier('2.16.840.1.101.3.4.2.3')
}

INVERSE_HASH_OID_LOOKUP = {v:k for k,v in HASH_OID_LOOKUP.items()}


RDN_TYPE_LOOKUP = {
    'CN': rfc2459.CommonName,
    'O': rfc2459.OrganizationName,
    'C': rfc2459.X520countryName,
    'L': rfc2459.UTF8String
}

RDN_OID_LOOKUP = {
    'CN': ObjectIdentifier([2, 5, 4, 3]),
    'O': ObjectIdentifier([2, 5, 4, 10]),
    'C': ObjectIdentifier([2, 5, 4, 6]),
    'L': ObjectIdentifier([2, 5, 4, 7])
}

# https://tools.ietf.org/html/rfc8017#appendix-A.2.4
SIGNING_ALG_OIDS = {
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


def parse_rdn(rdn_str: str) -> rfc2459.RDNSequence:
    rdn_parts = rdn_str.split(',')
    rdn_seq = rfc2459.RDNSequence()

    for i, part in enumerate(rdn_parts):
        k,v = [item.strip() for item in part.split('=')]

        attr = rfc2459.AttributeTypeAndValue()
        attr['type']  = RDN_OID_LOOKUP[k]
        attr['value'] = OctetString(encoder.encode(RDN_TYPE_LOOKUP[k](v)))

        rdn = rfc2459.RelativeDistinguishedName()
        rdn.setComponentByPosition(0, attr)
        rdn_seq.setComponentByPosition(i, rdn)

    return rdn_seq
