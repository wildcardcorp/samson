from samson.ace.decorators import has_exploit
from samson.ace.exploit import PlaintextPossession, KeyPossession


@has_exploit(PlaintextPossession)
@has_exploit(KeyPossession)
class MAC(object):
    def generate(self, *args, **kwargs):
        pass
