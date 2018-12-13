class Analyzer(object):
    """
    Base class for all Analyzers.

    Analyzers take in a byte-string and outputs a score where high scores match a context better.
    The score does not have to be absolute.
    """

    def __init__(self):
        pass


    def analyze(self, in_bytes: bytes) -> float:
        """
        Analyzes a bytes-like object and returns its "score".

        Parameters:
            in_bytes (bytes): The bytes-like object to be analyzed.

        Returns:
            float: The score.
        """
        raise NotImplementedError("The `analyze` method must be implemented by a subclass.")


    def select_highest_scores(self, in_list: list, num: int=1) -> list:
        """
        Analyzes a list `in_list`, sorts the list, and returns the top `num` scores.

        Parameters:
            in_list (list): The list of byte-like objects to be analyzed.
            num      (int): Number of results to return.

        Returns:
            list: `in_list` sorted and truncated.
        """
        return sorted(in_list, key=lambda item: self.analyze(item), reverse=True)[:num]
