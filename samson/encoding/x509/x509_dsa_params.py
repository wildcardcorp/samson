from pyasn1.type.univ import Integer, SequenceOf

class X509DSAParams(object):

    @staticmethod
    def encode(dsa_key):
        seq_of = SequenceOf()
        seq_of.extend([Integer(dsa_key.p), Integer(dsa_key.q), Integer(dsa_key.g)])

        return seq_of
