from samson.hashes.sha1 import SHA1
from samson.hashes.sha2 import SHA256
from pyasn1_modules import rfc2459
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import ObjectIdentifier, BitString, Any, OctetString

HASH_OID_LOOKUP = {
    SHA1: '',
    SHA256: ObjectIdentifier([2, 16, 840, 1, 101, 3, 4, 2, 1])
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


def parse_rdn(rdn_str: str):
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