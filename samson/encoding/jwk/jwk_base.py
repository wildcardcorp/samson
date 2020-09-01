from samson.core.base_object import BaseObject

class JWKBase(BaseObject):
    DEFAULT_MARKER = None
    DEFAULT_PEM = False
    USE_RFC_4716 = False

    def __init__(self, key, **kwargs):
        self.key = key
