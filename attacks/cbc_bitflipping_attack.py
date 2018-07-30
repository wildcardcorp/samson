from samson.utilities import *

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

class CBCBitflippingAttack(object):
    def __init__(self, oracle):
        self.oracle = oracle


    def execute(self, desired_injection, index=16):
        payload = 'a' * 16
        ciphertext = self.oracle.request(payload)
        edited_cipher = bytearray(ciphertext)
        edited_cipher[16:32] = xor_buffs(xor_buffs(edited_cipher[index:index + 16], desired_injection), payload.encode())
        return edited_cipher