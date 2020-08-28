from samson.encoding.dns_key.dns_key_base import DNSKeyBase
from samson.encoding.dns_key.general import DNSKeyAlgorithm
from samson.encoding.general import EncodingScheme
from samson.utilities.bytes import Bytes
from datetime import datetime


class DNSKeyPrivateBase(object):
    ALGS = None


    @classmethod
    def check(cls, buffer: bytes, **kwargs) -> bool:
        try:
            lines = buffer.split(b'\n')
            return b'Private-key-format:' in lines[0] and DNSKeyAlgorithm(int(lines[1].split(b' ')[1])) in cls.ALGS
        except Exception as _:
            return False


    @classmethod
    def build(cls, key: object, fields: dict, created: datetime=None, publish: datetime=None, activate: datetime=None, version: str='1.3', **kwargs):
        algorithm = kwargs.get('algorithm', cls.get_default_alg(key))
        alg_name  = kwargs.get('alg_name')
        if type(algorithm) is DNSKeyAlgorithm:
            alg      = algorithm.value
            alg_name = alg_name or algorithm.name.replace('_', '')
        else:
            alg      = algorithm
            alg_name = alg_name or DNSKeyAlgorithm(alg).name.replace('_', '')
        

        default_dt = datetime.utcnow()
        created  = created or default_dt
        publish  = publish or default_dt
        activate = activate or default_dt

        body = '\n'.join([f'{k}: {EncodingScheme.BASE64.encode(Bytes.wrap(v)).decode()}' for k,v in fields.items()])

        parts = [
            f'Private-key-format: v{version}',
            f'Algorithm: {alg} ({alg_name})',
            body,
            f'Created: {created.strftime("%Y%m%d%H%M%S")}',
            f'Publish: {publish.strftime("%Y%m%d%H%M%S")}',
            f'Activate: {activate.strftime("%Y%m%d%H%M%S")}',
        ]

        return b'\n'.join([p.encode('utf-8') for p in parts])


    @staticmethod
    def extract_fields(buffer: bytes) -> dict:
        lines  = buffer.split(b'\n')
        alg    = DNSKeyAlgorithm(int(lines[1].split(b' ')[1]))
        fields = dict([line.split(b': ') for line in lines[2:]])

        for k,v in fields.items():
            if k not in [b'Created', b'Publish', b'Activate']:
                fields[k] = EncodingScheme.BASE64.decode(v)

        return alg, fields
