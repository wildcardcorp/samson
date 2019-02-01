class IncrementingCounter(object):
    def __init__(self, value):
        self.value = value


    def __repr__(self):
        return f"<IncrementingCounter: value={self.value}>"

    def __str__(self):
        return self.__repr__()


    def get_value(self):
        val = self.value
        self.value += 1
        return val
