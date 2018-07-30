from samson.utilities import *
from samson.analyzers.english_analyzer import EnglishAnalyzer
from samson.attacks.repeating_xor_transposer import RepeatingXORTransposer
from samson.xor import find_key_size
import base64


def attempt_key(key, in_bytes):
    plaintext = xor_buffs(in_bytes, stretch_key(key, len(in_bytes)))
    #, is_readable_ascii(plaintext)
    return plaintext



with open('tests/test_repeating_xor.txt') as f:
    ciphertext = f.read().replace('\n', "").replace('\r', "")

decoded = base64.b64decode(ciphertext.encode())

analyzer = EnglishAnalyzer(attempt_key)
attack = RepeatingXORTransposer(analyzer, attempt_key)
print(attack.execute(decoded))