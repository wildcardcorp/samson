from enum import Enum

class Consequence(Enum):
    PLAINTEXT_RECOVERY = 0
    PLAINTEXT_MANIPULATION = 1
    KEY_RECOVERY = 2



class CompositeConsequence(object):
    OR  = lambda x, consequences: x in consequences
    AND = lambda x, consequences: x == consequences

    def __init__(self, consequences, composition_func):
        self.consequences = consequences
        self.composition_func = composition_func


    def __eq__(self, other):
        if type(other) is CompositeConsequence:
            other = other.consequences

        return self.composition_func(other, self.consequences)
