from samson.utilities import *
from samson.primitives.sha1 import SHA1

def _build_sha1_internal_state(hash_bytes):
    return [struct.unpack('>I', hash_bytes[i * 4: (i + 1) * 4])[0] for i in range(len(hash_bytes) // 4)]


def _sha1_length_extension(original, message, append_bytes, secret_len):
    chunks = _build_sha1_internal_state(original)
    glue = md_pad(message, len(message) + secret_len)[len(message):]
    #glue = generate_padding(len(message) + secret_len)

    fake_len = secret_len + len(message) + len(glue) + len(append_bytes)
    hash_obj = SHA1(chunks)
    hash_obj.pad_func = lambda msg: md_pad(message, fake_len, 'big')
    # hash_obj.update(append_bytes)
    # return message + glue + append_bytes, hash_obj.digest(fake_len)
    return message + glue + append_bytes, hash_obj.hash(append_bytes)



class HMACForgeryAttack(object):
    def __init__(self):
        pass


    def execute(self, original_signature, message, desired_injection, secret_len):
        return _sha1_length_extension(original_signature, message, desired_injection, secret_len)
