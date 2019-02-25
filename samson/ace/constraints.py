from samson.ace.consequence import Consequence, CompositeConsequence
from samson.ace.utility import Readable

class IdentityConstraint(Readable):
    def __init__(self):
        self.prevents_consequence = None
        self.needed_consequence   = None


class EncryptedConstraint(Readable):
    def __init__(self):
        self.prevents_consequence = Consequence.PLAINTEXT_RECOVERY
        self.needed_consequence   = CompositeConsequence([Consequence.PLAINTEXT_RECOVERY, Consequence.KEY_RECOVERY], CompositeConsequence.OR)


class MACConstraint(Readable):
    def __init__(self):
        self.prevents_consequence = Consequence.PLAINTEXT_MANIPULATION
        self.needed_consequence   = Consequence.KEY_RECOVERY
