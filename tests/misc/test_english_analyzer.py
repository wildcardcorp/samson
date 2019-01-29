from samson.analyzers.english_analyzer import EnglishAnalyzer
from samson.utilities.bytes import Bytes
from samson.utilities.general import shuffle
from .test_viterbi_decoder import SUPPOSED_ENGLISH
from copy import deepcopy
import unittest

ENGLISH_VALUES = [b'I\'m rated "R"...this is a warning, ya better void / Poets are paranoid, DJ\'s D-stroyed', b"Cuz I came back to attack others in spite- / Strike like lightnin', It's quite frightenin'!", b"But don't be afraid in the dark, in a park / Not a scream or a cry, or a bark, more like a spark;", b"Ya tremble like a alcoholic, muscles tighten up / What's that, lighten up! You see a sight but", b'Suddenly you feel like your in a horror flick / You grab your heart then wish for tomorrow quick!', b"Music's the clue, when I come your warned / Apocalypse Now, when I'm done, ya gone!", b"Haven't you ever heard of a MC-murderer? / This is the death penalty,and I'm servin' a", b'Death wish, so come on, step to this / Hysterical idea for a lyrical professionist!', b'Friday the thirteenth, walking down Elm Street / You come in my realm ya get beat!', b'This is off limits, so your visions are blurry / All ya see is the meters at a volume', b"Terror in the styles, never error-files / Indeed I'm known-your exiled!"] + [item.encode('utf-8') for item in SUPPOSED_ENGLISH]


class EnglishAnalyzerTestCase(unittest.TestCase):
    def setUp(self):
        self.analyzer = EnglishAnalyzer()


    def _check_best_sample(self, expected_val, all_values):
        best_sample = self.analyzer.select_highest_scores(all_values)[0]

        if best_sample != expected_val:
            print('Expected value not chosen as best sample!')
            print(expected_val)
            print(best_sample)

        self.assertEqual(best_sample, expected_val)



    # Tests the analyzer against a set containing a known English string and random bytes.
    def test_against_random(self):
        for english_val in ENGLISH_VALUES:
            all_values = [Bytes.random(len(english_val)) for _ in range(1000)] + [english_val]
            shuffle(all_values)

            self._check_best_sample(english_val, all_values)



    # Tests the analyzer against a set containing a known English string and shuffled versions of it.
    def test_against_shuffle(self):
        for english_val in ENGLISH_VALUES:
            english_val = Bytes(english_val)

            shuffled_vals = [deepcopy(english_val) for _ in range(10)]
            [shuffle(val) for val in shuffled_vals]

            all_values = shuffled_vals + [english_val]

            self.assertEqual(self.analyzer.select_highest_scores(all_values)[0], english_val)



    # Tests the analyzer against a set containing a known English string and mutated versions of it.
    def test_against_mutation(self):
        for english_val in ENGLISH_VALUES:
            english_val = Bytes(english_val)

            mutations = [Bytes.random(1).zfill(len(english_val)) for _ in range(100)]

            [shuffle(mutation) for mutation in mutations]
            mutated_vals = [english_val ^ mutation for mutation in mutations]

            all_values = mutated_vals + [english_val]
            self._check_best_sample(english_val, all_values)



    def test_against_edgecases(self):
        edge_cases = [
            b'I\'m rated "R"...this is a warning,\xcaya better void / Poets are paranoid, DJ\'s D-stroyed',
            b'I\'m rated "R"...this is a warning, ya better void / Poets are paranoidd DJ\'s D-stroyed',
            b'I\'m rated "R"...this is a warning, ya better voidy/ Poets are paranoid, DJ\'s D-stroyed',
            b'I\'m rated "R"...this is a warning,Bya better void / Poets are paranoid, DJ\'s D-stroyed',
            b'I\'m rated "R"...this isIa warning, ya better void / Poets are paranoid, DJ\'s D-stroyed'
        ]

        english_val = ENGLISH_VALUES[0]
        all_values = [english_val] + edge_cases

        self._check_best_sample(english_val, all_values)
