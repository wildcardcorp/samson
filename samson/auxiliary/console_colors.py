from enum import Enum

class ConsoleColors(Enum):
    WHITE   = 37
    GREEN   = 32
    CYAN    = 36
    YELLOW  = 33
    RED     = 31
    WH_RED  = 41
    BG_GRAY   = "48;2;39;40;34"
    BLUE      = "38;2;00;00;34"
    DEEP_RED  = "38;2;200;50;0"
    DEEP_GRAY = "38;2;125;125;125"
    LAVENDER  = "38;2;175;100;175"

PREFIX = '\033['
SUFFIX = '\033[0m'


def color_format(color: ConsoleColors, text: str):
    from samson.utilities.runtime import RUNTIME
    if type(color) is ConsoleColors:
        color = color.value

    if RUNTIME.use_color:
        formatted = f"{PREFIX}{color}m{text}{SUFFIX}"
    else:
        formatted = text

    return formatted
