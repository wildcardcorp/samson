from samson.encoding.dns_key.dns_key_private_base import DNSKeyPrivateBase
from samson.encoding.dns_key.dns_key_public_base import DNSKeyPublicBase
from samson.encoding.dns_key.general import DNSKeyAlgorithm
from samson.utilities.bytes import Bytes


class DNSKeyDHBase(object):
    ALGS = [DNSKeyAlgorithm.DH]

    @staticmethod
    def get_default_alg(dh_key: 'DiffieHellman') -> DNSKeyAlgorithm:
        return DNSKeyAlgorithm.DH



class DNSKeyDHPrivateKey(DNSKeyPrivateBase, DNSKeyDHBase):

    def encode(self, **kwargs) -> bytes:
        return self.build(
            fields={
                'Prime(p)': self.key.p,
                'Generator(g)': self.key.g,
                'Private_value(x)': self.key.key,
                'Public_value(y)': self.key.y
            }
        )


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'DiffieHellman':
        from samson.protocols.diffie_hellman import DiffieHellman

        version, alg, fields = DNSKeyPrivateBase.extract_fields(buffer)
        p = fields[b'Prime(p)'].int()
        g = fields[b'Generator(g)'].int()
        x = fields[b'Private_value(x)'].int()
        y = fields[b'Public_value(y)'].int()

        full_key = DNSKeyDHPrivateKey(DiffieHellman(g=g, p=p, key=x, y=y), alg, version, *DNSKeyDHPrivateKey.get_metadata(fields))
        return full_key




# https://tools.ietf.org/html/rfc2539#section-2
class DNSKeyDHPublicKey(DNSKeyPublicBase, DNSKeyDHBase):

    def encode(self, spacing: int=56, **kwargs) -> bytes:
        from samson.protocols.diffie_hellman import DHModToGroup
        y = Bytes(self.key.y)
        p = Bytes(self.key.p)
        g = Bytes(self.key.g)

        if self.key.p in DHModToGroup and not kwargs.get('explicit_group', False):
            p = Bytes(DHModToGroup[self.key.p])
            g = Bytes()

        payload = Bytes(len(p)).zfill(2) + p + Bytes(len(g)).zfill(2) + g + Bytes(len(y)).zfill(2) + y

        return self.build(payload, spacing=spacing)


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'RSA':
        from samson.protocols.diffie_hellman import DiffieHellman, DHGroupToMod
        pub_bytes = DNSKeyPublicBase.get_pub_bytes(buffer)

        # `p` length
        curr_idx = 2
        p_size   = pub_bytes[:curr_idx].int()

        # `p`
        p = pub_bytes[curr_idx:curr_idx+p_size].int()
        curr_idx += p_size

        # `g` length
        g_size = pub_bytes[curr_idx:curr_idx+2].int()
        curr_idx += 2

        # `g`
        g = pub_bytes[curr_idx:curr_idx+g_size].int()
        curr_idx += g_size

        # `y` length
        y_size = pub_bytes[curr_idx:curr_idx+2].int()
        curr_idx += 2

        # `y`
        y = pub_bytes[curr_idx:curr_idx+y_size].int()

        # Predefined "special" group
        if p < 256:
            p = DHGroupToMod[p]
            g = 2

        dh = DiffieHellman(key=1, p=p, g=g, y=y)
        full_key = DNSKeyDHPublicKey(dh, *DNSKeyPublicBase.get_metadata(buffer))
        return full_key
