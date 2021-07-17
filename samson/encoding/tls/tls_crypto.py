from samson.utilities.bytes import Bytes
from samson.core.base_object import BaseObject
from samson.encoding.tls.tls_core import Uint64, VarLenByteArray, TLSEnum, FixLenByteArray


class TLSHashAlgorithm(TLSEnum):
    NONE   = 0
    MD5    = 1
    SHA1   = 2
    SHA224 = 3
    SHA256 = 4
    SHA384 = 5
    SHA512 = 6


class TLSSignatureAlgorithm(TLSEnum):
    ANONYMOUS = 0
    RSA       = 1
    DSA       = 2
    ECDSA     = 3


class SCTVersion(TLSEnum):
    V1 = 0

LogID = FixLenByteArray(32)

class TLSSignedCertificateTimestamp(BaseObject):
    def __init__(self, version: int, log_id: Bytes, timestamp: int, ct_exts: list, hash_alg: TLSHashAlgorithm, sig_alg: TLSSignatureAlgorithm, signature: Bytes) -> None:
        self.version   = version
        self.log_id    = log_id
        self.timestamp = timestamp
        self.ct_exts   = ct_exts
        self.hash_alg  = hash_alg
        self.sig_alg   = sig_alg
        self.signature = signature


    def pack(self):
        data  = Bytes()
        data += self.version.pack()
        data += self.log_id.pack()
        data += self.timestamp.pack()
        data += self.ct_exts.pack()
        data += self.hash_alg.pack()
        data += self.sig_alg.pack()
        data += self.signature.pack()

        return VarLenByteArray(data).pack()



    @staticmethod
    def unpack(data: bytes):
        sct, data      = VarLenByteArray.unpack(data)
        version, sct   = SCTVersion.unpack(sct)
        log_id, sct    = LogID.unpack(sct)
        timestamp, sct = Uint64.unpack(sct)
        ct_exts, sct   = VarLenByteArray.unpack(sct)
        hash_alg, sct  = TLSHashAlgorithm.unpack(sct)
        sig_alg, sct   = TLSSignatureAlgorithm.unpack(sct)
        signature, sct = VarLenByteArray.unpack(sct)

        sct = TLSSignedCertificateTimestamp(
            version=version,
            log_id=log_id,
            timestamp=timestamp,
            ct_exts=ct_exts,
            hash_alg=hash_alg,
            sig_alg=sig_alg,
            signature=signature
        )

        return sct, data


class TLSSCTList(BaseObject):
    def __init__(self, scts: list) -> None:
        self.scts = scts
    

    def pack(self):
        data = Bytes()
        for sct in self.scts:
            data += sct.pack()
        
        return VarLenByteArray(data).pack()


    @staticmethod
    def unpack(data: bytes):
        sct_list, data = VarLenByteArray.unpack(data)
        scts = []

        while sct_list:
            sct, sct_list = TLSSignedCertificateTimestamp.unpack(sct_list)
            scts.append(sct)
        
        return TLSSCTList(scts), data

