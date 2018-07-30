from samson.utilities import *

class CBCBitflippingAttack(object):
    def __init__(self, oracle):
        self.oracle = oracle


    def execute(self, desired_injection, index=16):
        payload = 'a' * 16
        ciphertext = self.oracle.request(payload)
        edited_cipher = bytearray(ciphertext)
        edited_cipher[16:32] = xor_buffs(xor_buffs(edited_cipher[index:index + 16], desired_injection), payload.encode())
        return edited_cipher