from samson.utilities.manipulation import xor_buffs

# CTR will XOR the keystream with the ciphertext to decrypt the data. By injecting known plaintext,
# we can recover that block's keystream and XOR in our own plaintext. While this may seem extraneous given
# we can already inject a payload, this particular attack lends itself to bypassing validation functions.
# Imagine if an application encrypts a URL-encoded payload with its application key and gives it to us as way of keeping state.
# The developer assumes we can't modify the ciphertext without corrupting the string, so they trust the ciphertext
# when it's received.

# CBC will XOR the bitshift of the edited cipher block
# with the next blocks. To exploit this structure, we must
# craft a payload in reverse such that it creates our desired string.
# To do this, we need a known plaintext and a desired plaintext.
# We fill the targeted block with the known plaintext.
# We XOR our desired text, 'hiya;admin=true;', with the plaintext to find the "difference".
# Finally, we XOR the difference with the original cipher block.

# comment1=cooking
# %20MCs;userdata=
# aaaaaaaaaaaaaaaa
# ;comment2=%20lik
# e%20a%20pound%20
# of%20baconPPPPPP

class XORBitflippingAttack(object):
    # Expects an EncryptionOracle
    def __init__(self, oracle, block_size=16):
        self.oracle = oracle
        self.block_size = block_size


    def execute(self, desired_injection, index=16):
        payload = 'a' * self.block_size
        ciphertext = self.oracle.encrypt(payload)

        end_of_block = index + self.block_size
        edited_cipher = bytearray(ciphertext)
        edited_cipher[index:end_of_block] = xor_buffs(xor_buffs(edited_cipher[index:end_of_block], desired_injection), payload.encode())
        return edited_cipher