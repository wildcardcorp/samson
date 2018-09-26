from samson.auxiliary.markov_state import MarkovState

class MarkovChainHandler(object):
    def __init__(self):
        self.chain = MarkovState(count=1, probability=1, transitions={})
        self.curr_parsed_chain = self.chain



    def reset(self):
        self.curr_parsed_chain = self.chain

    
    def handle_token(self, token):
        if token in self.curr_parsed_chain.transitions:
            self.curr_parsed_chain.transitions[token].count += 1
        else:
            self.curr_parsed_chain.transitions[token] = MarkovState(count=1, probability=0, transitions={})

        self.curr_parsed_chain = self.curr_parsed_chain.transitions[token]



    def finalize(self):
        self.chain.calculate_chain_probs()
        return self.chain