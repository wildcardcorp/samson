class NotInvertibleException(Exception):
    def __init__(self, msg: str, parameters: dict):
        self.parameters = parameters
        super().__init__(msg)


class SearchspaceExhaustedException(Exception):
    pass


class CoercionException(Exception):
    pass


class InvalidPaddingException(Exception):
    pass


class ProbabilisticFailureException(Exception):
    pass
