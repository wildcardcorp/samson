class TokenizerHandler(object):
    """
    Base class for TokenizerHandlers.
    """

    def __init__(self):
        pass


    def reset(self):
        """Resets the internal for the next sample."""
        raise NotImplementedError()


    def handle_token(self, token: str):
        """Handles a new token being found."""
        raise NotImplementedError()


    def finalize(self) -> object:
        """Makes final modifications to state and returns result."""
        raise NotImplementedError()
