from samson.ace.decorators import has_exploit, creates_constraint
from samson.ace.exploit import PlaintextPossession
from samson.ace.constraints import MACConstraint


@has_exploit(PlaintextPossession)
@creates_constraint(MACConstraint())
class MAC(object):
    def generate(self, *args, **kwargs):
        pass
