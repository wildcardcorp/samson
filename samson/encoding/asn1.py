from samson.hashes.sha1 import SHA1
from samson.hashes.sha2 import SHA224, SHA256, SHA384, SHA512
from samson.hashes.md5 import MD5
from samson.hashes.md2 import MD2
from pyasn1_modules import rfc2459
from pyasn1.codec.der import encoder
from pyasn1.type.univ import ObjectIdentifier, OctetString

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


RDN_TYPE_LOOKUP = {
    'CN': rfc2459.CommonName,
    'O': rfc2459.OrganizationName,
    'C': rfc2459.X520countryName,
    'L': rfc2459.UTF8String,
    'ST': rfc2459.X520StateOrProvinceName,
    'OU': rfc2459.X520OrganizationalUnitName,
    'emailAddress': rfc2459.emailAddress,
    'serialNumber': rfc2459.CertificateSerialNumber,
    'streetAddress': rfc2459.StreetAddress

    # 'businessCategory': pyasn1_modules doesn't have this one
}

INVERSE_RDN_TYPE_LOOKUP = invert_dict(RDN_TYPE_LOOKUP)

RDN_OID_LOOKUP = {
    'CN': ObjectIdentifier([2, 5, 4, 3]),
    'O': ObjectIdentifier([2, 5, 4, 10]),
    'OU': ObjectIdentifier([2, 5, 4, 11]),
    'C': ObjectIdentifier([2, 5, 4, 6]),
    'L': ObjectIdentifier([2, 5, 4, 7]),
    'ST': ObjectIdentifier([2, 5, 4, 8]),
    'emailAddress': ObjectIdentifier('1.2.840.113549.1.9.1'),
    'serialNumber': ObjectIdentifier([2, 5, 4, 5]),
    'streetAddress': ObjectIdentifier([2, 5, 4, 9]),
    'businessCategory': ObjectIdentifier([2, 5, 4, 15]),
}

INVERSE_RDN_OID_LOOKUP = invert_dict(RDN_OID_LOOKUP)

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


def parse_rdn(rdn_str: str) -> rfc2459.RDNSequence:
    rdn_parts = rdn_str.split('=')
    rdn_seq   = rfc2459.RDNSequence()

    # Here we're careful of commas in RDNs
    # We also use 'key_idx' to keep track of the position
    # of the RDNs
    rdn_dict = {}
    key      = rdn_parts[0]
    key_idx  = [key]
    next_key = key

    for part in rdn_parts[1:-1]:
        parts = part.split(',')
        curr_val, next_key = ','.join(parts[:-1]), parts[-1]

        rdn_dict[key] = curr_val
        key           = next_key
        key_idx.append(key)

    rdn_dict[next_key] = rdn_parts[-1]


    for i, k in enumerate(key_idx[::-1]):
        v    = rdn_dict[k]
        attr = rfc2459.AttributeTypeAndValue()

        try:
            attr['type'] = RDN_OID_LOOKUP[k]

        # If the human-readable lookup fails, assume it's an OID
        except KeyError:
            attr['type'] = ObjectIdentifier(k)

        try:
            rdn_payload = RDN_TYPE_LOOKUP[k](v)

        # We need this for rfc2459.X520StateOrProvinceName
        except TypeError:
            rdn_payload = RDN_TYPE_LOOKUP[k]()
            rdn_payload.setComponentByPosition(0, v)

        attr['value'] = OctetString(encoder.encode(rdn_payload))

        rdn = rfc2459.RelativeDistinguishedName()
        rdn.setComponentByPosition(0, attr)
        rdn_seq.setComponentByPosition(i, rdn)

    return rdn_seq


def rdn_to_str(rdns: rfc2459.RDNSequence) -> str:
    from pyasn1.codec.der import decoder

    rdn_map = []
    for rdn in rdns[::-1]:
        oid_tuple = rdn[0]['type'].asTuple()
        try:
            rtype = INVERSE_RDN_OID_LOOKUP[ObjectIdentifier(oid_tuple)]

        # If we fail to convert it to a human readable, just convert to OID form
        except KeyError:
            rtype = '.'.join([str(i) for i in oid_tuple])

        rval  = str(decoder.decode(bytes(rdn[0]['value']))[0])
        rdn_map.append((rtype, rval))

    return ','.join(f'{rtype}={rval}' for rtype, rval in rdn_map)
