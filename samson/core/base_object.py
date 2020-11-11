from samson.auxiliary.console_colors import ConsoleColors, color_format
from samson.utilities.runtime import RUNTIME
import dill

FIELD_COLOR = '38;2;175;150;0'
INT_COLOR   = ConsoleColors.CYAN
STR_COLOR   = '38;2;200;110;0'
CLASS_COLOR = ConsoleColors.GREEN
BYTES_COLOR = ConsoleColors.DEEP_RED
NONE_COLOR  = ConsoleColors.DEEP_GRAY
BOOL_COLOR  = ConsoleColors.LAVENDER

def int_proc(a):
    is_long = a.bit_length() > 256
    if is_long and RUNTIME.minimize_output:
        a_str = f'...{str(a)[-70:]}'
    else:
        a_str = str(a)

    return color_format(INT_COLOR, a_str) + (f' ({a.bit_length()} bits)' if is_long else "")


def str_color(a):
    return color_format(STR_COLOR, str(a.__repr__()))

def cls_color(a):
    return color_format(CLASS_COLOR, str(a))

def color_text(color):
    return lambda a: color_format(color, str(a))


PROC_DICT = {
    'int': int_proc,
    'str': str_color,
    'bytes': color_text(STR_COLOR),
    'Bytes': color_text(BYTES_COLOR),
    'NoneType': color_text(NONE_COLOR),
    'bool': color_text(BOOL_COLOR),
    'type': cls_color
}


def process_field(field):
    cname = field.__class__.__name__
    if cname in PROC_DICT:
        return PROC_DICT[cname](field)
    else:
        return field.__repr__()


class BaseObject(object):
    def __reprdir__(self):
        return self.__dict__.keys()

    def __repr__(self):
        return f'<{cls_color(self.__class__.__name__)}: {", ".join([color_format(FIELD_COLOR, k) + "=" + process_field(self.__dict__[k]) for k in self.__reprdir__()])}>'

    def __str__(self):
        return self.__repr__()

    def __hash__(self):
        return object.__hash__(self)

    def __eq__(self, other):
        return self.__class__ == other.__class__ and self.__dict__ == other.__dict__


    def dumps(self):
        return dill.dumps(self)


    def save(self, filepath: str):
        with open(filepath, 'wb+') as f:
            dill.dump(self, f)
