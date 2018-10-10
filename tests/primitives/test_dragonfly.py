from samson.protocols.dragonfly import Dragonfly
import unittest

class DragonflyTestCase(unittest.TestCase):
    def test_dragonfly(self):
        key = b'a really bad key'
        df1 = Dragonfly(key)
        df2 = Dragonfly(key)
        ch1 = df1.get_challenge()
        ch2 = df2.get_challenge()

        self.assertEqual(df1.derive_key(ch2), df2.derive_key(ch1))