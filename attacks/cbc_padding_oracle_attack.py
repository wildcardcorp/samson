from samson.utilities import *

# https://grymoire.wordpress.com/2014/12/05/cbc-padding-oracle-attacks-simplified-key-concepts-and-pitfalls/
class CBCPaddingOracleAttack(object):
    def __init__(self, oracle, iv):
        self.oracle = oracle
        self.iv = iv


    def execute(self, ciphertext):
        blocks = get_blocks(ciphertext)
        reversed_blocks = blocks[::-1]

        plaintexts = []

        for i, block in enumerate(reversed_blocks):
            plaintext = b''

            if i == len(reversed_blocks) - 1:
                preceding_block = self.iv
            else:
                preceding_block = reversed_blocks[i + 1]

            for byte in range(len(block)):
                working_chars = []
                for possible_char in range(256):
                    test_byte = struct.pack('B', possible_char)
                    payload = test_byte + plaintext
                    prefix = b'\x00' * (16 - len(payload))

                    padding = xor_buffs(struct.pack('B', len(payload)) * (len(payload)), payload)

                    fake_block = prefix + padding
                    exploit_block = xor_buffs(fake_block, preceding_block)
                    new_cipher = exploit_block + block

                    if self.oracle.request(bytes(new_cipher)):
                        if(self.oracle.request(bytes(exploit_block + block))):
                            working_chars.append(test_byte)

                plaintext = working_chars[-1] + plaintext

            plaintexts.append(plaintext)
        return pkcs7_unpad(b''.join(plaintexts[::-1]))