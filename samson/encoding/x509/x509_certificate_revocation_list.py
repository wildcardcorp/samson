from datetime import datetime
from pyasn1.type import tag
from samson.utilities.bytes import Bytes
from typing import List
from pyasn1.type.univ import Sequence, SequenceOf
from samson.encoding.x509.x509_extension import X509Extension
from samson.encoding.asn1 import parse_time, build_time, resolve_alg, verify_signature, build_signature_alg
from samson.core.base_object import BaseObject
from pyasn1_modules import rfc5280
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import namedtype
from samson.encoding.x509.x509_signature import X509Signature
from samson.encoding.x509.x509_rdn import RDNSequence


class CRLEntry(Sequence):
    pass


CRLEntry.componentType = namedtype.NamedTypes(
    namedtype.NamedType('userCertificate', rfc5280.CertificateSerialNumber()),
    namedtype.NamedType('revocationDate', rfc5280.Time()),
    namedtype.OptionalNamedType('crlEntryExtensions', rfc5280.Extensions())
)

# https://datatracker.ietf.org/doc/html/rfc5280#section-5.1
class X509CRLEntry(BaseObject):
    def __init__(self, user_certificate: str, revocation_date: datetime, extensions: List[X509Extension]=None) -> None:
        self.user_certificate = user_certificate
        self.revocation_date  = revocation_date
        self.extensions       = extensions
    

    @staticmethod
    def parse(crl_entry: Sequence) -> 'X509CRLEntry':
        user_certificate = int(crl_entry['userCertificate'])
        revocation_date  = parse_time(crl_entry['revocationDate'])

        extensions = None
        if crl_entry['crlEntryExtensions'].isValue:
            extensions = [X509Extension.parse(ext) for ext in crl_entry['crlEntryExtensions']]

        return X509CRLEntry(user_certificate=user_certificate, revocation_date=revocation_date, extensions=extensions)


    def build(self):
        user_cert = rfc5280.CertificateSerialNumber(self.user_certificate)

        entry = CRLEntry()
        entry['userCertificate'] = user_cert
        entry['revocationDate']  = build_time(self.revocation_date)

        if self.extensions:
            extensions = rfc5280.Extensions()
            
            for extension in self.extensions:
                extensions.append(extension.build())

            entry['crlEntryExtensions'] = extensions

        return entry



class X509CertificateRevocationList(BaseObject):
    def __init__(self, issuer: RDNSequence, this_update: datetime, next_update: datetime=None, crl_entries: List[X509CRLEntry]=None, extensions: List[X509Extension]=None, version: int=2, signing_alg: X509Signature=None, signature_value: bytes=None) -> None:
        self.version         = version
        self.issuer          = issuer
        self.this_update     = this_update
        self.next_update     = next_update
        self.crl_entries     = crl_entries
        self.extensions      = extensions
        self.signing_alg     = signing_alg
        self.signature_value = signature_value
    

    def build(self, signing_key: 'EncodablePKI'=None):
        tbs_certlist = rfc5280.TBSCertList()

        # Issuer RDN
        issuer = rfc5280.Name()
        issuer.setComponentByPosition(0, self.issuer.build())
        tbs_certlist['issuer'] = issuer

        # Update times
        tbs_certlist['thisUpdate'] = build_time(self.this_update)

        if self.next_update:
            tbs_certlist['nextUpdate'] = build_time(self.next_update)


        # Version is optional
        if self.version is not None:
            tbs_certlist['version'] = tbs_certlist['version'].clone(self.version)


        # Entries are optional
        if self.crl_entries:
            crl_seq = SequenceOf()
            crl_seq.extend([crl.build() for crl in self.crl_entries])

            tbs_certlist['revokedCertificates'] = crl_seq
        

        if self.extensions:
            extensions = rfc5280.Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
            
            for extension in self.extensions:
                extensions.append(extension.build())

            tbs_certlist['crlExtensions'] = extensions
    

        # Ripped this from X509Cert
        signing_alg   = self.signing_alg or signing_key.X509_SIGNING_DEFAULT.value
        signature_alg = build_signature_alg(signing_alg, signing_key)

        tbs_certlist['signature'] = signature_alg


        # Inject or compute the signature
        if self.signature_value is not None:
            sig_value = Bytes.wrap(self.signature_value).int()
        else:
            encoded_tbs = encoder.encode(tbs_certlist)
            sig_value   = signing_alg.sign(signing_key, encoded_tbs)


        crl = rfc5280.CertificateList()
        crl['tbsCertList'] = tbs_certlist
        crl['signatureAlgorithm'] = signature_alg
        crl['signature'] = sig_value

        return crl


    @staticmethod
    def parse(crl_bytes: bytes) -> 'X509CertificateRevocationList':
        crl, _ = decoder.decode(crl_bytes, asn1Spec=rfc5280.CertificateList())

        tbs_certlist = crl['tbsCertList']
        version = int(tbs_certlist['version'])
        issuer  = RDNSequence.parse(tbs_certlist['issuer'][0])
        this_update = parse_time(tbs_certlist['thisUpdate'])

        next_update = None
        if tbs_certlist['nextUpdate'].isValue:
            next_update = parse_time(tbs_certlist['nextUpdate'])

        crl_entries = None
        if tbs_certlist['revokedCertificates'].isValue:
            crl_entries = [X509CRLEntry.parse(crl_entry) for crl_entry in tbs_certlist['revokedCertificates']]


        extensions = None
        if tbs_certlist['crlExtensions'].isValue:
            extensions = [X509Extension.parse(ext) for ext in tbs_certlist['crlExtensions']]
        

        signature_alg   = resolve_alg(tbs_certlist['signature'])
        signature_value = Bytes(int(crl['signature']))


        return X509CertificateRevocationList(
            issuer=issuer,
            version=version,
            this_update=this_update,
            next_update=next_update,
            crl_entries=crl_entries,
            extensions=extensions,
            signing_alg=signature_alg,
            signature_value=signature_value
        )


    @staticmethod
    def verify(buffer: bytes, verification_key: object) -> bool:
        # Decode the full CRL and get the encoded TBSCertList
        crl, _left_over = decoder.decode(buffer, asn1Spec=rfc5280.CertificateList())
        return verify_signature(verification_key, crl['tbsCertList']['signature'], crl['tbsCertList'], crl['signature'])
