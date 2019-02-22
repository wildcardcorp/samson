from samson.ace.decorators import has_exploit, creates_constraint
from samson.ace.exploit import KeyPossession
from samson.ace.constraints import EncryptedConstraint

@has_exploit(KeyPossession)
@creates_constraint(EncryptedConstraint())
class EncryptionAlg(object):
    def encrypt(self, *args, **kwargs):
        pass


    def decrypt(self, *args, **kwargs):
        pass
