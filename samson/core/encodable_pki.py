from samson.encoding.general import PKIEncoding
from samson.encoding.pem import pem_decode

ORDER = [PKIEncoding.DNS_KEY, PKIEncoding.JWK, PKIEncoding.OpenSSH, PKIEncoding.SSH2, PKIEncoding.X509_CSR, PKIEncoding.X509_CERT, PKIEncoding.X509, PKIEncoding.PKCS8, PKIEncoding.PKCS1]

class EncodablePKI(object):
    PUB_ENCODINGS  = {}
    PRIV_ENCODINGS = {}

    @classmethod
    def import_key(cls, buffer: bytes, passphrase: bytes=None) -> 'EncodablePKI':
        """
        Builds a PKI instance from DER and/or PEM-encoded bytes.

        Parameters:
            buffer     (bytes): DER and/or PEM-encoded bytes.
            passphrase (bytes): Passphrase to decrypt DER-bytes (if applicable).

        Returns:
            object: PKI instance.
        """
        if buffer.startswith(b'----'):
            buffer = pem_decode(buffer, passphrase)

        for encoding in ORDER:
            for encoding_type in [cls.PRIV_ENCODINGS, cls.PUB_ENCODINGS]:

                if encoding in encoding_type:
                    encoder = encoding_type[encoding]

                    if encoder.check(buffer, passphrase=passphrase):
                        return encoder.decode(buffer, passphrase=passphrase)

        raise ValueError(f"Unable to parse provided {cls} key.")



    def export_public_key(self, encoding: PKIEncoding=PKIEncoding.X509, **kwargs) -> bytes:
        """
        Exports the only the public parameters of the PKI instance into encoded bytes.

        Parameters:
            encoding (PKIEncoding): Encoding scheme to use. Support dependent on PKI type.

        Returns:
            object: Encoding of PKI instance.
        """
        if encoding not in self.PUB_ENCODINGS:
            raise ValueError(f'Unsupported public encoding "{encoding}" for "{self.__class__}"')

        return self.PUB_ENCODINGS[encoding](self, **kwargs)



    def export_private_key(self, encode_pem: bool=True, encoding: PKIEncoding=PKIEncoding.PKCS8, marker: str=None, encryption: str=None, passphrase: bytes=None, iv: bytes=None, **kwargs) -> bytes:
        """
        Exports the full PKI instance into encoded bytes.

        Parameters:
            encode_pem      (bool): Whether or not to PEM-encode as well.
            encoding (PKIEncoding): Encoding scheme to use. Support dependent on PKI type.
            marker           (str): Marker to use in PEM formatting (if applicable).
            encryption       (str): (Optional) RFC1423 encryption algorithm (e.g. 'DES-EDE3-CBC').
            passphrase     (bytes): (Optional) Passphrase to encrypt DER-bytes (if applicable).
            iv             (bytes): (Optional) IV to use for CBC encryption.

        Returns:
            bytes: Bytes-encoded PKI instance.
        """
        if encoding not in self.PRIV_ENCODINGS:
            raise ValueError(f'Unsupported private encoding "{encoding}" for "{self.__class__}"')

        return self.PRIV_ENCODINGS[encoding](self, **kwargs)
