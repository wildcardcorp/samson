from samson.utilities import *
from samson.primitives.sha1 import Sha1Hash, generate_padding

def _build_sha1_internal_state(hash_bytes):
    return [struct.unpack('>I', hash_bytes[i * 4: (i + 1) * 4])[0] for i in range(len(hash_bytes) // 4)]


def _sha1_length_extension(original, message, append_bytes, secret_len):
    chunks = _build_sha1_internal_state(original)
    glue = generate_padding(len(message) + secret_len)

    fake_len = secret_len + len(message) + len(glue) + len(append_bytes)
    hash_obj = Sha1Hash(chunks)
    hash_obj.update(append_bytes)
    return message + glue + append_bytes, hash_obj.digest(fake_len)



class HMACForgeryAttack(object):
    def __init__(self):
        pass


    def execute(self, original_signature, message, desired_injection, secret_len):
        return _sha1_length_extension(original_signature, message, desired_injection, secret_len)
