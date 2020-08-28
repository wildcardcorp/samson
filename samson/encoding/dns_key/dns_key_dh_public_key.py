from samson.encoding.dns_key.dns_key_base import DNSKeyBase
from samson.encoding.dns_key.general import DNSKeyAlgorithm
from samson.utilities.bytes import Bytes

# https://tools.ietf.org/html/rfc2539#section-2
class DNSKeyDHPublicKey(DNSKeyBase):
    ALGS = [DNSKeyAlgorithm.DH]


    @staticmethod
    def get_default_alg(dh_key: 'DiffieHellman') -> DNSKeyAlgorithm:
        return DNSKeyAlgorithm.DH


    @staticmethod
    def encode(dh_key: 'DiffieHellman', **kwargs) -> bytes:
        from samson.protocols.diffie_hellman import DHModToGroup, DHGroupToMod
        y = Bytes(dh_key.y)
        p = Bytes(dh_key.p)
        g = Bytes(dh_key.g)

        if dh_key.p in DHModToGroup and not kwargs.get('explicit_group', False):
            p = Bytes(DHModToGroup[dh_key.p])
            g = Bytes()

        payload = Bytes(len(p)).zfill(2) + p + Bytes(len(g)).zfill(2) + g + Bytes(len(y)).zfill(2) + y

        if 'spacing' not in kwargs:
            kwargs['spacing'] = 56

        return DNSKeyDHPublicKey.build(dh_key, payload,  **kwargs)


    @staticmethod
    def decode(buffer: bytes, **kwargs) -> 'RSA':
        from samson.protocols.diffie_hellman import DiffieHellman, DHGroupToMod
        pub_bytes = DNSKeyBase.get_pub_bytes(buffer)

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
        return dh
