# Takes in a list of tokens
# Generates a Markov Chain
# Must work for delimited and non-delimited inputs
# Must grab the longest string possible

class Tokenizer(object):
    def __init__(self, token_list, token_handler, delimiter=' '):
        self.token_list = token_list
        self.token_handler = token_handler
        self.delimiter = delimiter

        self.processed_tokens = {}

        for token in self.token_list:
            curr_dict = self.processed_tokens

            for char in token:
                if char not in curr_dict:
                    curr_dict[char] = {}
                curr_dict = curr_dict[char]

            # '$$' is the flag for end of string
            curr_dict['$$'] = None



    def tokenize(self, samples):

        ################
        #    STEP 1    #
        # Create chain #
        ################
        token_handler = self.token_handler()

        for sample in samples:
            parts = sample.split(self.delimiter)
            token_handler.reset()

            for part in parts:
                token = ''
                last_largest_substring = ''
                curr_token_chain = self.processed_tokens

                # We'll use a while loop, so we have more control over the counter
                char_counter = 0

                while char_counter < len(part):
                    char = part[char_counter]
                    #print("Starting {} {}".format(char_counter, char))

                    if char in curr_token_chain:
                        token += char
                        curr_token_chain = curr_token_chain[char]

                        # This is a valid substring, and there's only an end-of-token flag left
                        # OR
                        # This is a valid substring, and we've reached the end of the part
                        if curr_token_chain == {'$$': None} or ('$$' in curr_token_chain and char_counter + 1 == len(part)):
                            token_handler.handle_token(token)
                            #print("Found end {}".format(token))

                            token = ''
                            last_largest_substring = ''
                            curr_token_chain = self.processed_tokens

                        # This is a valid substring, but it may not be the whole string.
                        # We'll keep track of it in case it is.
                        elif '$$' in curr_token_chain:
                            #print("Found valid substring {}".format(token))
                            last_largest_substring = token


                    # It's not a valid token; we'll need to rollback.
                    # Example:

                    # tokenizer = Tokenizer(['abc', 'hello', 'adam', 'hiya'])
                    # chain = tokenizer.generate_chain(['adabcadam'])
                    # For 'adabcadam', we'll get to 'ada', but 'b' will not be a valid state.
                    # We then must rollback to 'd'.
                    else:
                        # The entire thing isn't a valid token, but a substring is.
                        substring_mod = 0
                        if last_largest_substring != '':
                            #token = last_largest_substring
                            token_handler.handle_token(last_largest_substring)
                            substring_mod = len(last_largest_substring) - 1
                            #print("Found valid substring {} from invalid".format(last_largest_substring))

                        #print("Resetting counter: token:{}, len(token): {}, substring_mod: {}".format(token, len(token), substring_mod))
                        char_counter -= len(token) - substring_mod
                        token = ''
                        last_largest_substring = ''
                        curr_token_chain = self.processed_tokens

                    char_counter += 1


        return token_handler.finalize()
        # ###########################
        # #         STEP 2          #
        # # Calculate probabilities #
        # ###########################
        # parsed_chain.calculate_chain_probs()