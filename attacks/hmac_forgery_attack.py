from samson.utilities.padding import md_pad
from samson.hashes.sha1 import SHA1
import struct

def _build_sha1_internal_state(hash_bytes):
    return [struct.unpack('>I', hash_bytes[i * 4: (i + 1) * 4])[0] for i in range(len(hash_bytes) // 4)]


def _sha1_length_extension(original, message, append_bytes, secret_len):
    chunks = _build_sha1_internal_state(original)
    glue = md_pad(message, len(message) + secret_len, 'big')[len(message):]

    fake_len = secret_len + len(message) + len(glue) + len(append_bytes)

    new_hash = SHA1(chunks)
    new_hash.pad_func = lambda msg: md_pad(msg, fake_len, 'big')

    return message + glue + append_bytes, new_hash.hash(append_bytes)


class HMACForgeryAttack(object):
    def __init__(self):
        pass


    def execute(self, original_signature, message, desired_injection, secret_len):
        return _sha1_length_extension(original_signature, message, desired_injection, secret_len)
