# Takes in a list of tokens
# Generates a Markov Chain
# Must work for delimited and non-delimited inputs
# Must grab the longest string possible
from samson.auxiliary.token_list_handler import TokenListHandler
from samson.auxiliary.tokenizer_handler import TokenizerHandler

class Tokenizer(object):
    """
    Splits a string into the longest 'tokens' parameterized bt the `token_list`. Works for delimited
    and non-delimited inputs.
    """

    def __init__(self, token_list: list, token_handler: TokenizerHandler=TokenListHandler, delimiter: str=' '):
        """
        Parameters:
            token_list                (list): List of possible tokens, e.g. wordlist.
            token_handler (TokenizerHandler): Instantiable class.
            delimiter                  (str): (Optional) Delimiter to split samples apart.
        """
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



    def tokenize(self, samples: list) -> object:
        """
        Tokenizes a list of samples.

        Parameters:
            samples (list): List of string samples to break into tokens.
        
        Returns:
            object: The finalized return of the `token_handler`.
        """
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

                    if char in curr_token_chain:
                        token += char
                        curr_token_chain = curr_token_chain[char]

                        # This is a valid substring, and there's only an end-of-token flag left
                        # OR
                        # This is a valid substring, and we've reached the end of the part
                        if curr_token_chain == {'$$': None} or ('$$' in curr_token_chain and char_counter + 1 == len(part)):
                            token_handler.handle_token(token)

                            token = ''
                            last_largest_substring = ''
                            curr_token_chain = self.processed_tokens

                        # This is a valid substring, but it may not be the whole string.
                        # We'll keep track of it in case it is.
                        elif '$$' in curr_token_chain:
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
                            token_handler.handle_token(last_largest_substring)
                            substring_mod = len(last_largest_substring) - 1


                        char_counter -= len(token) - substring_mod
                        token = ''
                        last_largest_substring = ''
                        curr_token_chain = self.processed_tokens

                    char_counter += 1


        return token_handler.finalize()
