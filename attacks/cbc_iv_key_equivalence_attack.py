from samson.utilities import *
from samson.primitives.aes_cbc import decrypt_aes_cbc

class CBCIVKeyEquivalenceAttack(object):
    def __init__(self, oracle):
        self.oracle = oracle


    def execute(self, ciphertext):
        edited_cipher = bytearray(ciphertext)
        edited_cipher[16:32] = b'\x00' * 16
        edited_cipher[32:48] = edited_cipher[:16]

        recovered_bytes = self.oracle.request(bytes(edited_cipher))
        print(recovered_bytes)
        blocks = get_blocks(recovered_bytes)

        derived_iv = bytes(xor_buffs(blocks[0], blocks[2]))
        return derived_iv, decrypt_aes_cbc(derived_iv, derived_iv, ciphertext)