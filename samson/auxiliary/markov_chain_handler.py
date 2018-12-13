from samson.auxiliary.markov_state import MarkovState
from samson.auxiliary.tokenizer_handler import TokenizerHandler

class MarkovChainHandler(TokenizerHandler):
    """
    Tokenize Handler that builds Markov chains.
    """

    def __init__(self):
        self.chain = MarkovState(count=1, probability=1, transitions={})
        self.curr_parsed_chain = self.chain


    def reset(self):
        self.curr_parsed_chain = self.chain


    def handle_token(self, token: str):
        """
        Handles a new token being found.

        Parameters:
            token (str): Found token.
        """
        if token in self.curr_parsed_chain.transitions:
            self.curr_parsed_chain.transitions[token].count += 1
        else:
            self.curr_parsed_chain.transitions[token] = MarkovState(count=1, probability=0, transitions={})

        self.curr_parsed_chain = self.curr_parsed_chain.transitions[token]



    def finalize(self) -> MarkovState:
        """
        Calculates the probabilities down the chains,

        Returns:
            MarkovState: The Markov chain.
        """
        self.chain.calculate_chain_probs()
        return self.chain
