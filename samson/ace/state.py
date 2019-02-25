from samson.ace.constraints import IdentityConstraint
from samson.ace.consequence import Consequence
from samson.ace.exploit import IdentityExploit

class State(object):
    def __init__(self, child=None, owner=None, constraints=[], exploits=[]):
        self.child = child
        self.parent = None
        self.owner = owner
        self.constraints = constraints
        self.exploits = exploits
        self.requirements_satisfied = []
        self.exposed_state = self

        if child:
            child.parent = self


    def __repr__(self):
        return f"<State: child={self.child}, owner={self.owner}, constraints={self.constraints}, exploits={self.exploits}, requirements_satisfied={self.requirements_satisfied}>"

    def __str__(self):
        return self.__repr__()


    def propagate_requirement_satisfied(self, requirement):
        current_state = self

        while current_state != None:
            current_state.requirements_satisfied.append(requirement)
            current_state = current_state.child



class Plaintext(State):
    def __init__(self):
        super().__init__(constraints=[IdentityConstraint()], exploits=[IdentityExploit(Consequence.PLAINTEXT_RECOVERY), IdentityExploit(Consequence.PLAINTEXT_MANIPULATION)])
