from samson.auxiliary.console_colors import ConsoleColors, PREFIX, SUFFIX
from logging import Formatter
from copy import copy

LEVEL_MAPPING = {
    'DEBUG'   : ConsoleColors.WHITE,
    'INFO'    : ConsoleColors.GREEN,
    'WARNING' : ConsoleColors.YELLOW,
    'ERROR'   : ConsoleColors.RED,
    'CRITICAL': ConsoleColors.WH_RED
}

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
