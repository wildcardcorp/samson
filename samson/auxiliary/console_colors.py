from enum import Enum

class ConsoleColors(Enum):
    WHITE  = 37
    GREEN  = 32
    YELLOW = 33
    RED    = 31
    WH_RED = 41

PREFIX = '\033['
SUFFIX = '\033[0m'
