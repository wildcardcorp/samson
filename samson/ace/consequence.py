from enum import Enum


class Requirement(Enum):
    EVENTUALLY_DECRYPTS = 0


class Consequence(Enum):
    PLAINTEXT_RECOVERY = 0
    ENCRYPTION_BYPASS = 1
    KEY_RECOVERY = 2



class CompositeConsequence(object):
    OR  = lambda x, consequences: x in consequences
    AND = lambda x, consequences: x == consequences

    def __init__(self, consequences, composition_func):
        self.consequences = consequences
        self.composition_func = composition_func


    def __repr__(self):
        return f'CompositeConsequence: {self.consequences}>'


    def __eq__(self, other):
        if type(other) is CompositeConsequence:
            other = other.consequences

        return self.composition_func(other, self.consequences)




class Manipulation(Enum):
    PT_BIT_LEVEL = 0
    PT_MULTIPLICATIVE = 1

    def __hash__(self):
        return self.value

    def __eq__(self, other):
        return type(self) == type(other) and (self.value == other.value or (self in MANIPULATION_GRAPH and other in MANIPULATION_GRAPH[self]))


MANIPULATION_GRAPH = {
    Manipulation.PT_MULTIPLICATIVE: [Manipulation.PT_BIT_LEVEL]
}
