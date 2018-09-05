# Takes in a list of tokens
# Generates a Markov Chain
# Must work for delimited and non-delimited inputs
from samson.auxiliary.markov_state import MarkovState

class Tokenizer(object):
    def __init__(self, token_list, delimiter=' '):
        self.token_list = token_list
        self.delimiter = delimiter

        self.processed_tokens = {}

        for token in self.token_list:
            curr_dict = self.processed_tokens

            for char in token:
                if char not in curr_dict:
                    curr_dict[char] = {}
                curr_dict = curr_dict[char]



    def _add_to_chain(self, token, parsed_chain):
        print(token)
        if token in parsed_chain.transitions:
            print('Adding one to {}'.format(token))
            parsed_chain.transitions[token].probability += 1
        else:
            parsed_chain.transitions[token] = MarkovState(1, {})


    def _calculate_chain_probs(self, chain):
        total_count = sum([subchain.probability for token, subchain in chain.transitions.items()])
        for _token, subchain in chain.transitions.items():
            subchain.probability /= total_count
            self._calculate_chain_probs(subchain)


    def generate_chain(self, samples):

        ################
        #    STEP 1    #
        # Create chain #
        ################
        parsed_chain = MarkovState(1, {})

        for sample in samples:
            parts = sample.split(self.delimiter)
            curr_parsed_chain = parsed_chain

            for part in parts:
                token = ''
                curr_token_chain = self.processed_tokens

                # We'll use a while loop, so we have more control over the counter
                char_counter = 0

                while char_counter < len(part):
                    char = part[char_counter]
                    print(char)

                    if char in curr_token_chain:
                        token += char
                        curr_token_chain = curr_token_chain[char]

                        if curr_token_chain == {}:
                            self._add_to_chain(token, curr_parsed_chain)
                            curr_parsed_chain = curr_parsed_chain.transitions[token]

                            token = ''
                            curr_token_chain = self.processed_tokens

                    # It's not a valid token; we'll need to rollback
                    # Example:

                    # tokenizer = Tokenizer(['abc', 'hello', 'adam', 'hiya'])
                    # chain = tokenizer.generate_chain(['adabcadam'])
                    # For 'adabcadam', we'll get to 'ada', but 'b' will not be a valid state.
                    # We then must rollback to 'd'.
                    else:
                        char_counter -= len(token) - 1
                        token = ''
                        curr_token_chain = self.processed_tokens
                        

                    # # End of current token; reset state
                    # else:
                    #     print('END OF TOKEN')
                    #     print(token)
                    #     if token != '':
                    #         self._add_to_chain(token, curr_parsed_chain)
                    #         curr_parsed_chain = curr_parsed_chain.transitions[token]

                    #         # Need to stay on this character since this could be the beginning of the
                    #         # next word
                    #         char_counter -= 1

                    #     token = ''
                    #     curr_token_chain = self.processed_tokens
                    char_counter += 1

                # # End of part; make sure we commit the last token
                # if token != '':
                #     self._add_to_chain(token, curr_parsed_chain)
                #     curr_parsed_chain = curr_parsed_chain.transitions[token]


        ###########################
        #         STEP 2          #
        # Calculate probabilities #
        ###########################
        self._calculate_chain_probs(parsed_chain)

        return parsed_chain
