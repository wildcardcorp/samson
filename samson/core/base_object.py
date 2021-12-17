from samson.auxiliary.console_colors import ConsoleColors, color_format
from samson.utilities.runtime import RUNTIME
from copy import copy, deepcopy
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


def list_proc(a):
    is_long = len(a) > 10
    if is_long and RUNTIME.minimize_output:
        a_str = f'{str(a[:10])[:-1]}...'
    else:
        a_str = str(a)

    return f'{a_str} ({len(a)} items)'


def str_color(a):
    return color_format(STR_COLOR, str(a.__repr__()))

def cls_color(a):
    return color_format(CLASS_COLOR, str(a))

def color_text(color):
    return lambda a: color_format(color, str(a))


PROC_DICT = {
    'int': int_proc,
    'str': str_color,
    'list': list_proc,
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
        return str(field)


def default_printer(fields):
    return f': {", ".join(fields)}'


class BaseObject(object):
    def __reprdir__(self):
        return self.__dict__.keys()
    

    def __internal_repr(self,  use_color: bool):
        if use_color:
            field_formatter = lambda k: color_format(FIELD_COLOR, k)
            class_formatter = cls_color
        else:
            field_formatter = lambda k: k
            class_formatter = lambda c: c


        field_str = ""
        if self.__reprdir__():
            fields = []

            for k in self.__reprdir__():
                key = ""
                val = getattr(self, k)

                if k != '__raw__':
                    key = field_formatter(k) + "="
                    val = process_field(val)

                fields.append(key + val)

            field_str = default_printer(fields)

        return f'<{class_formatter(self.__class__.__name__)}{field_str}>'


    def _repr_pretty_(self, p, cycle) -> str:
        return p.text(self.__internal_repr(True))


    def __repr__(self) -> str:
        return self.__internal_repr(False)


    def __str__(self):
        return self.__repr__()

    def __hash__(self):
        dic_items  = []
        for k,v in self.__dict__.items():
            if type(v) is list:
                v = tuple(v)
            dic_items.append((k, v))
            
        return hash((self.__class__, tuple(dic_items)))

    def __eq__(self, other):
        return self.__class__ == other.__class__ and self.__dict__ == other.__dict__


    def dumps(self):
        return dill.dumps(self)


    def save(self, filepath: str):
        with open(filepath, 'wb+') as f:
            dill.dump(self, f)


    def copy(self):
        return copy(self)


    def deepcopy(self):
        return deepcopy(self)
