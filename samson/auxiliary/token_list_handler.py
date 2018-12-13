from samson.auxiliary.tokenizer_handler import TokenizerHandler

class TokenListHandler(TokenizerHandler):
    """
    TokenizerHandler that builds a list.
    """

    def __init__(self):
        self.list = []


    def reset(self):
        pass


    def handle_token(self, token: str):
        """
        Handles tokens found by a Tokenizer.

        Parameters:
            token (str): Token found.
        """
        self.list.append(token)


    def finalize(self) -> list:
        """
        Returns the list of tokens.
        """
        return self.list
