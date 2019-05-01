from samson.ace.consequence import Consequence, CompositeConsequence, Manipulation
from samson.ace.utility import Readable


class Constraint(Readable):
    def apply(self, state):
        state.constraints.append(self)


class PropagatingConstraint(Constraint):
    def apply(self, state):
        current_state = state

        while current_state != None:
            current_state.constraints.append(self)
            current_state = current_state.child


class IdentityConstraint(Constraint):
    def __init__(self, needed_consequence=None):
        self.prevents_consequence = None
        self.needed_consequence   = None


class EncryptedConstraint(Constraint):
    def __init__(self):
        self.prevents_consequence = Consequence.PLAINTEXT_RECOVERY
        self.needed_consequence   = CompositeConsequence([Consequence.ENCRYPTION_BYPASS, Consequence.KEY_RECOVERY], CompositeConsequence.OR)


class MACConstraint(PropagatingConstraint):
    def __init__(self, owner):
        self.prevents_consequence = Manipulation.PT_BIT_LEVEL
        self.needed_consequence   = Consequence.KEY_RECOVERY
        self.owner = owner


    def __eq__(self, other):
        return type(self) == type(other) and self.owner == other.owner




# TODO: Needs to propagate
class RSAConstraint(PropagatingConstraint):
    def __init__(self):
        self.prevents_consequence = Manipulation.PT_BIT_LEVEL
        self.needed_consequence   = Consequence.KEY_RECOVERY
