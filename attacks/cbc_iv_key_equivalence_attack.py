from samson.utilities.manipulation import get_blocks, xor_buffs
from samson.primitives.aes_cbc import decrypt_aes_cbc

class CBCIVKeyEquivalenceAttack(object):
    def __init__(self, oracle, block_size=16):
        self.oracle = oracle
        self.block_size = block_size


    def execute(self, ciphertext):
        edited_cipher = bytearray(ciphertext)
        edited_cipher[self.block_size:self.block_size * 2] = b'\x00' * self.block_size
        edited_cipher[self.block_size * 2:self.block_size * 3] = edited_cipher[:self.block_size]

        recovered_bytes = self.oracle.request(bytes(edited_cipher))
        print(recovered_bytes)
        blocks = get_blocks(recovered_bytes, self.block_size)

        derived_iv = bytes(xor_buffs(blocks[0], blocks[2]))
        return derived_iv, decrypt_aes_cbc(derived_iv, derived_iv, ciphertext, block_size=self.block_size)