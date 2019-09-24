from pyasn1.type.univ import Integer, SequenceOf

class X509DiffieHellmanParams(object):

    @staticmethod
    def encode(dh_key):
        seq_of = SequenceOf()
        seq_of.extend([Integer(dh_key.p), Integer(dh_key.g)])

        return seq_of
