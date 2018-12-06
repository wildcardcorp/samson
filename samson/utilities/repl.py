start_exec = """from __future__ import division
from sympy import *
x, y, z, t = symbols('x y z t')
k, m, n = symbols('k m n', integer=True)
f, g, h = symbols('f g h', cls=Function)

from samson.all import *
from fastecdsa.curve import *

init_printing()

import logging
logging.basicConfig(format='%(asctime)s - %(name)s [%(levelname)s] %(message)s', level=logging.DEBUG)
"""

LOGO = """
                                                                
  /$$$$$$$  /$$$$$$  /$$$$$$/$$$$   /$$$$$$$  /$$$$$$  /$$$$$$$ 
 /$$_____/ |____  $$| $$_  $$_  $$ /$$_____/ /$$__  $$| $$__  $$
|  $$$$$$   /$$$$$$$| $$ \ $$ \ $$|  $$$$$$ | $$  \ $$| $$  \ $$
 \____  $$ /$$__  $$| $$ | $$ | $$ \____  $$| $$  | $$| $$  | $$
 /$$$$$$$/|  $$$$$$$| $$ | $$ | $$ /$$$$$$$/|  $$$$$$/| $$  | $$
|_______/  \_______/|__/ |__/ |__/|_______/  \______/ |__/  |__/
                                                                
                                                                
                                                                """

def start_repl():
    """
    Executes the samson REPL.
    """
    import IPython
    import sys
    from samson import VERSION

    banner = f"""
{LOGO}
    v{VERSION} -- https://github.com/wildcardcorp/samson

Python {sys.version}
IPython {IPython.__version__}
"""

    IPython.start_ipython(display_banner=False, exec_lines=[start_exec, f'print("""{banner}""")'])