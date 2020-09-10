from samson.auxiliary.console_colors import ConsoleColors, color_format
from types import FunctionType
from pygments.styles.monokai import MonokaiStyle
from pygments.lexers import Python3Lexer
from pygments.formatters import TerminalTrueColorFormatter
from pygments import highlight
import shutil
import re

UNDEFINED_PARAM_RE = re.compile(r'`[A-Za-z0-9() _+-]+`')

TERM_SIZE = shutil.get_terminal_size((80, 20))

LEXER     = Python3Lexer()
FORMATTER = TerminalTrueColorFormatter(style=MonokaiStyle)

NEWLINE = '\n'
TAB     = '\t'
QUOTE   = '\"'


def type_format(cls):
    return color_format(ConsoleColors.GREEN, cls)


def param_format(text):
    return color_format(ConsoleColors.CYAN, text)


def undefined_param_format(text):
    return color_format(ConsoleColors.YELLOW, text)


def code_format(code, bg_size):
    lines   = code.splitlines()
    bg_size = max(TERM_SIZE.columns // 2 - 10, bg_size)

    code = NEWLINE.join([line.ljust(bg_size) for line in lines])
    highlighted = highlight(code, LEXER, FORMATTER).rstrip(NEWLINE)
    return color_format(ConsoleColors.BG_GRAY, highlighted)



class DocParameter(object):
    def __init__(self, name: str, cls: type, desc: str):
        self.name = name
        self.cls = cls
        self.desc = desc


class ClassTuple(object):
    def __init__(self, *items):
        self.items = items

    def __str__(self):
        return f"({', '.join([item for item in self.items])})"


class DocReturns(object):
    def __init__(self, cls: type, desc: str):
        def strip_namespace(cls):
            return type_format(str(cls).split('.')[-1].lstrip("<class '").rstrip("'>"))

        if type(cls) is type:
            cls = strip_namespace(cls)
        elif type(cls) is tuple:
            cls = ClassTuple(*[strip_namespace(item) for item in cls])
        else:
            cls = type_format(cls)

        self.cls = cls
        self.desc = desc


class DocReference(object):
    def __init__(self, name: str, url: str):
        self.name = name
        self.url  = url


class DocExample(object):
    def __init__(self, code: str, result: str):
        self.code   = code
        self.result = result


    def __repr__(self):
        lines   = self.code.splitlines()
        bg_size = max([len(l) for l in lines])+5
        return NEWLINE.join([TAB + code_format(f'>>> {line}', bg_size=bg_size) for line in lines]) + NEWLINE + NEWLINE.join([TAB + code_format(line, bg_size=bg_size) for line in str(self.result).split('$N$')])


    def __str__(self):
        return self.__repr__()


    def load(self):
        from IPython import get_ipython
        get_ipython().set_next_input(self.code)




def gen_doc(description: str=None, parameters: list=None, returns: DocReturns=None, examples: list=None, references: list=None):
    def _doc(func):
        parameters_str = ""
        returns_str    = ""
        references_str = ""
        examples_str   = ""

        if parameters:
            largest_param = max([len(param.name) + len(param.cls) for param in parameters])
            parameters_str = f"""

    Parameters:
    {NEWLINE.join([f'{TAB}{param_format(param.name)}{" " * (largest_param + 1 - (len(param.name) + len(param.cls)))}({type_format(param.cls)}): {param.desc}' for param in parameters])}"""


        if returns:
            returns_str = f"""

    Returns:
    {TAB}{returns.cls}: {returns.desc}"""


        if examples:
            examples_str = f"""

    Examples:
    {(NEWLINE + NEWLINE).join([f'{TAB}>>> # Example {idx}{NEWLINE}' + str(example) for idx, example in enumerate(examples)])}"""


        if references:
            references_str = f"""

    References:
    {NEWLINE.join([f'{TAB}{QUOTE + ref.name + QUOTE + " " if ref.name else ""}{ref.url}' for ref in references])}"""



        # Color references to parameters
        def parameterize(d_str):
            for param in parameters:
                d_str = d_str.replace(f'`{param.name}`', param_format(param.name))

            return d_str


        def undefined_parameterize(d_str):
            return UNDEFINED_PARAM_RE.sub(lambda match: undefined_param_format(match.group()[1:-1]), d_str)


        parameterized_desc = undefined_parameterize(parameterize(description))
        parameterized_ret  = undefined_parameterize(parameterize(returns_str))
        param_params       = undefined_parameterize(parameterize(parameters_str))

        func.__doc__ = f"{parameterized_desc}{param_params}{parameterized_ret}{examples_str}{references_str}"
        func.examples = examples
        func.is_rich = True
        return func
    return _doc



def parse_doc(func):
    doc   = func.__doc__
    lines = doc.splitlines()

    def get_line_idx(text):
        found = [idx for idx, line in enumerate(lines) if text in line]
        return found[0] if found else -1

    headers = ['Parameters', 'Returns', 'Examples', 'References']
    indices = [('Description', 0)] + [(header, get_line_idx(header + ':')) for header in headers]
    parsed  = {}


    # Parse out sections in order
    for idx, (header, line_idx) in enumerate(indices):
        if line_idx >= 0:
            next_idx = [next_idx for _, next_idx in indices[idx+1:] if next_idx > 0]

            if next_idx:
                relevant_lines = lines[line_idx+1:next_idx[0]]
            else:
                relevant_lines = lines[line_idx+1:]

            relevant_lines = [l.strip() for l in relevant_lines]
            relevant_lines = [l for l in relevant_lines if l]
            parsed[header] = relevant_lines


    # Handle each case separately
    description = ' '.join([line.strip() for line in parsed['Description']]).strip()

    params = []
    if 'Parameters' in parsed:
        for param in parsed['Parameters']:
            split = param.split()
            p_name, p_type = split[:2]
            p_desc = ' '.join(split[2:])

            params.append(DocParameter(p_name, p_type.lstrip('(').rstrip('):'), p_desc))


    returns = None
    if 'Returns' in parsed:
        split   = parsed['Returns'][0].split(':')
        r_type  = split[0].rstrip(':')
        r_desc  = split[1].strip()

        returns = DocReturns(r_type, r_desc)


    _examples = []
    examples  = []
    if 'Examples' in parsed:
        exs         = parsed['Examples']
        output_idxs = [-1] + [idx for idx, ex in enumerate(exs) if ">>>" not in ex]

        for idx, out_idx in enumerate(output_idxs[1:]):
            code = NEWLINE.join([ex.lstrip(">>> ") for ex in exs[output_idxs[idx]+1:out_idx]])
            _examples.append(DocExample(code, exs[out_idx]))


        # Handle multiline output (adjacent indices/no code)
        for idx, example in enumerate(_examples):
            if example.code:
                examples.append(example)
            else:
                examples[-1].result += '$N$' + example.result


    references = []
    if 'References' in parsed:
        refs = parsed['References']

        for ref in refs:
            url_start = ref.index('http')

            if url_start > -1:
                dref = DocReference(ref[:url_start], ref[url_start:])
            else:
                dref = DocReference(ref, "")

            references.append(dref)


    return description, params, returns, examples, references


def richdoc(func):
    if func.__doc__ and not hasattr(func, 'is_rich'):
        return gen_doc(*parse_doc(func))(func)
    else:
        return func



def autodoc(g):
    def process_func(name, func):
        g[name] = richdoc(func)


    for name, obj in g.items():
        if hasattr(obj, '__module__') and 'samson' in obj.__module__:
            t_o = type(obj)

            if t_o is FunctionType:
                process_func(name, obj)

            elif issubclass(t_o, type):
                for member in dir(obj):
                    try:
                        mem = getattr(obj, member)
                        if type(mem) is FunctionType:
                            richdoc(mem)
                    except AttributeError:
                        pass
