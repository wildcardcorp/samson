from samson.ace.decorators import has_exploit
from samson.ace.exploit import PlaintextPossession


@has_exploit(PlaintextPossession)
class MAC(object):
    def generate(self, *args, **kwargs):
        pass
