class TokenListHandler(object):
    def __init__(self):
        self.list = []

    def reset(self):
        pass

    
    def handle_token(self, token):
        self.list.append(token)


    def finalize(self):
        return self.list