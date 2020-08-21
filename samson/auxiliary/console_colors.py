from enum import Enum

class ConsoleColors(Enum):
    WHITE   = 37
    GREEN   = 32
    CYAN    = 36
    YELLOW  = 33
    RED     = 31
    WH_RED  = 41
    BG_GRAY = "48;2;39;40;34"

PREFIX = '\033['
SUFFIX = '\033[0m'
