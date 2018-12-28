class Progress(object):
    """
    Progress baseclass. Gives the user a tangible, contextualized object to update. `tqdm`-like interface.
    """

    def __init__(self, iterable: object):
        """
        Parameters:
            iterable (iterable): Iterable to report progress on.
        """
        self.iterable = iterable


    def update(self, amount: int):
        """
        Updates the Progress with the amount achieved. This class does nothing.

        Parameters:
            amount (int): Amount of progress achieved (incremental).
        """
        pass


    def __iter__(self):
        return iter(self.iterable)
