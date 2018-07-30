from samson.analyzers.english_analyzer import EnglishAnalyzer
from samson.attacks.repeating_xor_transposer import RepeatingXORTransposer
from samson.primitives.xor import find_key_size, decrypt
import base64
import unittest


class RepeatingXORTranspositionTestCase(unittest.TestCase):
    def test_prepend_attack(self):
        with open('tests/test_repeating_xor.txt') as f:
            ciphertext = f.read().replace('\n', "").replace('\r', "")

        decoded = base64.b64decode(ciphertext.encode())

        analyzer = EnglishAnalyzer(decrypt)
        attack = RepeatingXORTransposer(analyzer, decrypt)

        recovered_plaintext = attack.execute(decoded)
        print(recovered_plaintext)