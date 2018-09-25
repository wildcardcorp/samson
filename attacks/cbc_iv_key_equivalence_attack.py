from samson.utilities.bytes import Bytes



class CBCIVKeyEquivalenceAttack(object):
    def __init__(self, oracle, block_size=16):
        self.oracle = oracle
        self.block_size = block_size


    def execute(self, ciphertext):
        edited_cipher = Bytes.wrap(bytes(ciphertext))

        edited_cipher[self.block_size:self.block_size * 2] = b'\x00' * self.block_size
        edited_cipher[self.block_size * 2:self.block_size * 3] = edited_cipher[:self.block_size]

        recovered_bytes = self.oracle.request(bytes(edited_cipher))
        blocks = Bytes(recovered_bytes).chunk(self.block_size)

        derived_iv = blocks[0] ^ blocks[2]
        return derived_iv