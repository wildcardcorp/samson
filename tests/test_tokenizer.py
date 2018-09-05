from samson.auxiliary.tokenizer import Tokenizer
import unittest

class TokenizerTestCase(unittest.TestCase):
    def test_basecase(self):
        tokenizer = Tokenizer(['abc', 'hello', 'adam', 'hiya'])
        chain = tokenizer.generate_chain(['abcdhiya', 'helloadam'])

        # Verify first level tokens
        self.assertTrue(all([token in chain.transitions for token in ['abc', 'hello']]))

        # Verify second level tokens
        self.assertTrue(all([token in chain.transitions['abc'].transitions for token in ['hiya']]))
        self.assertTrue(all([token in chain.transitions['hello'].transitions for token in ['adam']]))

        # Verify first level probabilities
        self.assertEqual(chain.transitions['abc'].probability, 0.5)
        self.assertEqual(chain.transitions['hello'].probability, 0.5)

        # Verify second level probabilities
        self.assertEqual(chain.transitions['abc'].transitions['hiya'].probability, 1.0)
        self.assertEqual(chain.transitions['hello'].transitions['adam'].probability, 1.0)



    def test_rollback(self):
        tokenizer = Tokenizer(['abc', 'hello', 'adam', 'hiya'])
        chain = tokenizer.generate_chain(['adabcadam'])

        # Verify first level tokens
        self.assertTrue(all([token in chain.transitions for token in ['abc']]))

        # Verify second level tokens
        self.assertTrue(all([token in chain.transitions['abc'].transitions for token in ['adam']]))

        # Verify first level probabilities
        self.assertEqual(chain.transitions['abc'].probability, 1.0)

        # Verify second level probabilities
        self.assertEqual(chain.transitions['abc'].transitions['adam'].probability, 1.0)



    def test_longest_substring(self):
        tokenizer = Tokenizer(['abc', 'hello', 'adam', 'hiya', 'hiyabois'])
        chain = tokenizer.generate_chain(['abcdhiya', 'helloadam', 'adabcadam', 'whoishiyabois'])

        # Verify first level tokens
        self.assertTrue(all([token in chain.transitions for token in ['abc', 'hello', 'hiyabois']]))

        # Verify second level tokens
        self.assertTrue(all([token in chain.transitions['abc'].transitions for token in ['hiya', 'adam']]))
        self.assertTrue(all([token in chain.transitions['hello'].transitions for token in ['adam']]))
        self.assertTrue(chain.transitions['hiyabois'].transitions == {})

        # Verify we did NOT take the substring
        self.assertFalse('hiya' in chain.transitions)

        # Verify first level probabilities
        self.assertEqual(chain.transitions['abc'].probability, 0.5)
        self.assertEqual(chain.transitions['hello'].probability, 0.25)
        self.assertEqual(chain.transitions['hiyabois'].probability, 0.25)


        # Verify second level probabilities
        self.assertEqual(chain.transitions['abc'].transitions['hiya'].probability, 0.5)
        self.assertEqual(chain.transitions['abc'].transitions['adam'].probability, 0.5)
        self.assertEqual(chain.transitions['hello'].transitions['adam'].probability, 1.0)

    
