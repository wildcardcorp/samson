from samson.auxiliary.viterbi_decoder import ViterbiDecoder
from samson.analysis.general import levenshtein_distance
import unittest

SUPPOSED_ENGLISH = [
    "Somebody once told me the world is gonna roll me",
    "I ain't the sharpest tool in the shed",
    "She was looking kind of dumb with her finger and her thumb",
    "In the shape of an \"L\" on her forehead",
    "Well the years start coming and they don't stop coming",
    "Fed to the rules and I hit the ground running",
    "Didn't make sense not to live for fun",
    "Your brain gets smart but your head gets dumb",
    "So much to do, so much to see",
    "So what's wrong with taking the back streets?",
    "You'll never know if you don't go",
    "You'll never shine if you don't glow"
]

class ViterbiDecoderTestCase(unittest.TestCase):
    def test_gauntlet(self):
        vd = ViterbiDecoder()

        for text in SUPPOSED_ENGLISH:
            correct = text.replace("'", '').replace('?', '').replace('"', "").upper().split(' ')
            smashed_together = ''.join(correct)

            most_probable_decoding = vd.score(smashed_together)[1]
            self.assertLessEqual(levenshtein_distance(most_probable_decoding, correct), 2)
