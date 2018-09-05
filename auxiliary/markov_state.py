class MarkovState(object):
    def __init__(self, count, probability, transitions):
        self.count = count
        self.probability = probability
        self.transitions = transitions



    # Recursively turn counts into probabilities
    def calculate_chain_probs(self):
        total_count = sum([subchain.count for token, subchain in self.transitions.items()])

        for _token, subchain in self.transitions.items():
            subchain.probability = subchain.count / total_count
            subchain.calculate_chain_probs()