from typing import List
from samson.encoding.x509.oids import OID
from samson.encoding.x509.x509_extension import X509Extension
from samson.core.base_object import BaseObject
from pyasn1_modules import rfc5280
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import  ObjectIdentifier, OctetString
from pyasn1.type.char import IA5String


class X509Attribute(BaseObject):
    ATTR_TYPE = None

    def _build(self, value: object):
        attr              = rfc5280.Attribute()
        attr['type']      = ObjectIdentifier(self.ATTR_TYPE.value)
        attr['values'][0] = attr['values'][0].clone(OctetString(encoder.encode(value)))

        return attr


    def build(self) -> rfc5280.Attribute:
        """
        For arbitrary attributes.
        """
        oid = self.oid
        if hasattr(oid, 'value'):
            oid = self.oid.value

        attr              = rfc5280.Attribute()
        attr['type']      = ObjectIdentifier(oid)
        attr['values'][0] = attr['values'][0].clone(OctetString(self.data))

        return attr


    @staticmethod
    def parse(attribute: rfc5280.Attribute) -> 'X509Attribute':
        attr_type = str(attribute['type'])

        try:
            attr_type = OID(attr_type)

            for subclass in X509Attribute.__subclasses__():
                if subclass.ATTR_TYPE == attr_type:
                    return subclass.parse(bytes(attribute['values'][0]))

        except ValueError:
            pass

        attr      = X509Attribute()
        attr.oid  = attr_type
        attr.data = bytes(attribute['values'][0 ])
        return attr



class X509ExtensionRequest(X509Attribute):
    ATTR_TYPE = OID.EXTENSION_REQUEST

    def __init__(self, extensions: List[X509Extension]) -> None:
        self.extensions = extensions
    

    def build(self) -> rfc5280.Attribute:
        exts = rfc5280.Extensions()

        for ext in self.extensions:
            exts.append(ext.build())

        return super()._build(exts)


    @staticmethod
    def parse(data: bytes) -> 'X509ExtensionRequest':
        exts, _ = decoder.decode(data, asn1Spec=rfc5280.Extensions())
        return X509ExtensionRequest([X509Extension.parse(ext) for ext in exts])



# https://docs.microsoft.com/en-us/windows/win32/seccertenroll/supported-attributes
class X509MicrosoftExtensionRequest(X509ExtensionRequest, X509Attribute):
    ATTR_TYPE = OID.MICROSOFT_SPC_CERT_EXTENSIONS_OBJID



class X509MicrosoftOSVersion(X509Attribute):
    ATTR_TYPE = OID.MICROSOFT_szOID_OS_VERSION

    def __init__(self, version: str) -> None:
        self.version = version
    

    def build(self) -> rfc5280.Attribute:
        return super()._build(IA5String(self.version))


    @staticmethod
    def parse(data: bytes) -> 'X509MicrosoftOSVersion':
        version, _ = decoder.decode(data)
        return X509MicrosoftOSVersion(version=str(version))
