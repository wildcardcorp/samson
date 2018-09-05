class MarkovState(object):
    def __init__(self, probability, transitions):
        self.probability = probability
        self.transitions = transitions