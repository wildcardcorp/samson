class Readable(object):
    def __repr__(self):
        return f"<{self.__class__}: {self.__dict__}>"

    def __str__(self):
        return self.__repr__()

    def __eq__(self, other):
        return type(self) == type(other) and self.__dict__ == other.__dict__
