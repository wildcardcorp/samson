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

class FieldFormatter(object):
    TYPE = None

    @staticmethod
    def parse(field, use_color: bool=True):
        t = field.__class__.__name__

        for subclass in FieldFormatter.__subclasses__():
            if t == subclass.TYPE:
                return subclass.parse(field, use_color)
        
        return str(field)


class IntFormatter(FieldFormatter):
    TYPE = 'int'

    @staticmethod
    def parse(field, use_color: bool):
        is_long = field.bit_length() > 256
        if is_long and RUNTIME.minimize_output:
            a_str = f'...{str(field)[-70:]}'
        else:
            a_str = str(field)
        
        if use_color:
            val = color_format(INT_COLOR, a_str)
        else:
            val = a_str

        return val + (f' ({field.bit_length()} bits)' if is_long else "")


class ListFormatter(FieldFormatter):
    TYPE = 'list'

    @staticmethod
    def parse(field, use_color: bool):
        is_long = len(field) > 10

        def list_subformat(field):
            return '[' + ','.join([item_formatter(elem, use_color) for elem in field]) + ']'

        if is_long and RUNTIME.minimize_output:
            a_str = f'{list_subformat(field[:10])[:-1]}...'
        else:
            a_str = list_subformat(field)

        return f'{a_str} ({len(field)} items)'



class GenericFormatted(FieldFormatter):
    COLOR = None

    @classmethod
    def parse(cls, field, use_color: bool):
        val = str(field)

        if use_color:
            return color_format(cls.COLOR, val)
        else:
            return val


class ClassFormatter(GenericFormatted, FieldFormatter):
    TYPE  = 'type'
    COLOR = CLASS_COLOR

class StringFormatter(GenericFormatted, FieldFormatter):
    TYPE  = 'str'
    COLOR = STR_COLOR

    @staticmethod
    def parse(field, use_color: bool):
        val = repr(str(field))

        if use_color:
            return color_format(StringFormatter.COLOR, val)
        else:
            return val


class BytesFormatter(GenericFormatted, FieldFormatter):
    TYPE  = 'bytes'
    COLOR = STR_COLOR

class ManagedBytesFormatter(GenericFormatted, FieldFormatter):
    TYPE  = 'Bytes'
    COLOR = BYTES_COLOR

class NoneFormatter(GenericFormatted, FieldFormatter):
    TYPE  = 'NoneType'
    COLOR = NONE_COLOR

class BoolFormatter(GenericFormatted, FieldFormatter):
    TYPE  = 'bool'
    COLOR = BOOL_COLOR



def default_printer(fields):
    return f': {", ".join(fields)}'


def item_formatter(val, use_color):
    if hasattr(val, '__boformat__'):
        val = val.__boformat__(use_color)
    else:
        val = FieldFormatter.parse(val, use_color)
    
    return val


class BaseObject(object):
    def __reprdir__(self):
        return self.__dict__.keys()
    

    def __boformat__(self, use_color: bool, curr_depth: int=0, max_depth: int=100):
        field_str = ""
        if self.__reprdir__():
            fields = []

            for k in self.__reprdir__():
                key = ""
                val = getattr(self, k)

                if k != '__raw__':
                    if use_color:
                        k = color_format(FIELD_COLOR, k)

                    key = k + "="

                    if hasattr(val, '__boformat__') and curr_depth < max_depth:
                        val = val.__boformat__(use_color, curr_depth=curr_depth+1, max_depth=max_depth)
                    else:
                        val = FieldFormatter.parse(val, use_color)

                fields.append(key + val)

            field_str = default_printer(fields)
        
        cname = self.__class__.__name__

        if use_color:
            cname = color_format(CLASS_COLOR, cname)

        return f'<{cname}{field_str}>'


    def __repr__(self) -> str:
        return self.__boformat__(True)


    def __str__(self) -> str:
        return self.__boformat__(False)


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
