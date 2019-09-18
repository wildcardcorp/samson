from logging import Formatter
from copy import copy
from enum import Enum


class ConsoleColors(Enum):
    WHITE  = 37
    GREEN  = 32
    YELLOW = 33
    RED    = 31
    WH_RED = 41


LEVEL_MAPPING = {
    'DEBUG'   : ConsoleColors.WHITE,
    'INFO'    : ConsoleColors.GREEN,
    'WARNING' : ConsoleColors.YELLOW,
    'ERROR'   : ConsoleColors.RED,
    'CRITICAL': ConsoleColors.WH_RED
}

PREFIX = '\033['
SUFFIX = '\033[0m'

class ColoredFormatter(Formatter):
    """
    Based on https://stackoverflow.com/a/46482050
    """

    def __init__(self, fmt: str):
        Formatter.__init__(self, fmt)

    def format(self, record: object):
        record = copy(record)
        level  = record.levelname
        seq    = LEVEL_MAPPING.get(level, ConsoleColors.WHITE)
        record.levelname = f'{PREFIX}1;{seq.value}m{level}{SUFFIX}'
        return Formatter.format(self, record)
