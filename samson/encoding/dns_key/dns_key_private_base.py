from samson.encoding.dns_key.general import DNSKeyAlgorithm
from samson.encoding.general import EncodingScheme
from samson.core.base_object import BaseObject
from samson.utilities.bytes import Bytes
from datetime import datetime

_TIME_FORMAT = '%Y%m%d%H%M%S'

class DNSKeyPrivateBase(BaseObject):

    def __init__(self, key: object, algorithm: DNSKeyAlgorithm=None, version: str='1.3', created: datetime=None, publish: datetime=None, activate: datetime=None, **kwargs):
        self.key   = key

        default_dt = datetime.utcnow()
        self.created  = created or default_dt
        self.publish  = publish or default_dt
        self.activate = activate or default_dt
        self.version  = version

        if type(algorithm) is int:
            algorithm = DNSKeyAlgorithm(algorithm)

        if not algorithm:
            algorithm = self.get_default_alg(key)

        self.algorithm = algorithm
        self.alg_name  = None



    @classmethod
    def check(cls, buffer: bytes, **kwargs) -> bool:
        try:
            lines = buffer.split(b'\n')
            return b'Private-key-format:' in lines[0] and DNSKeyAlgorithm(int(lines[1].split(b' ')[1])) in cls.ALGS
        except Exception as _:
            return False


    def build(self, fields: dict):
        alg      = self.algorithm.value
        alg_name = self.alg_name or self.algorithm.name
        alg_name = alg_name.replace('_', '')

        body = '\n'.join([f'{k}: {EncodingScheme.BASE64.encode(Bytes.wrap(v)).decode()}' for k,v in fields.items()])

        parts = [
            f'Private-key-format: v{self.version}',
            f'Algorithm: {alg} ({alg_name})',
            body,
            f'Created: {self.created.strftime(_TIME_FORMAT)}',
            f'Publish: {self.publish.strftime(_TIME_FORMAT)}',
            f'Activate: {self.activate.strftime(_TIME_FORMAT)}',
        ]

        return b'\n'.join([p.encode('utf-8') for p in parts])


    @staticmethod
    def extract_fields(buffer: bytes) -> dict:
        lines   = buffer.split(b'\n')
        version = lines[0].split(b' ')[-1][1:].decode()
        alg     = DNSKeyAlgorithm(int(lines[1].split(b' ')[1]))
        fields  = dict([line.split(b': ') for line in lines[2:]])

        for k,v in fields.items():
            if k not in [b'Created', b'Publish', b'Activate']:
                fields[k] = EncodingScheme.BASE64.decode(v)

        return version, alg, fields


    @staticmethod
    def get_metadata(fields: dict) -> (datetime, datetime, datetime):
        return [datetime.strptime(fields[dt].decode(), _TIME_FORMAT) for dt in [b'Created', b'Publish', b'Activate']]
