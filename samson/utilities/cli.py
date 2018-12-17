start_exec = """from __future__ import division
from sympy import *
x, y, z, t = symbols('x y z t')
k, m, n = symbols('k m n', integer=True)
f, g, h = symbols('f g h', cls=Function)

from samson.all import *
from fastecdsa.curve import *

init_printing()

import logging
logging.basicConfig(format='%(asctime)s - %(name)s [%(levelname)s] %(message)s', level=logging.WARNING)
logging.getLogger("samson").setLevel(logging.DEBUG)
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



from samson.hashes.all import MD4, MD5, BLAKE2b, BLAKE2s, Keccak, RIPEMD160, SHA1, SHA224, SHA256, SHA384, SHA512, SHA3
from samson.public_key.all import RSA, DSA, ECDSA, EdDSA
from fastecdsa.curve import P192, P224, P256, P384, P521, secp192k1, secp224k1, secp256k1, brainpoolP160r1, brainpoolP192r1, brainpoolP224r1, brainpoolP256r1, brainpoolP320r1, brainpoolP384r1, brainpoolP512r1

HASHES = {
    'blake2b': BLAKE2b,
    'blake2s': BLAKE2s,
    'keccak': Keccak,
    'md4': MD4,
    'md5': MD5,
    'ripem160': RIPEMD160,
    'sha1': SHA1,
    'sha224': SHA224,
    'sha256': SHA256,
    'sha364': SHA384,
    'sha512': SHA512,
    'sha3_224': SHA3.K224,
    'sha3_256': SHA3.K256,
    'sha3_384': SHA3.K384,
    'sha3_512': SHA3.K512,
    'shake128': SHA3.SHAKE128,
    'shake256': SHA3.SHAKE256
}

PKI = {
    'rsa': RSA,
    'dsa': DSA,
    'ecdsa': ECDSA,
    'eddsa': EdDSA
}


CURVES = {
    'p192': P192,
    'p224': P224,
    'p256': P256,
    'p384': P384,
    'p521': P521,
    'nistp192': P192,
    'nistp224': P224,
    'nistp256': P256,
    'nistp384': P384,
    'nistp521': P521,
    'secp192r1': P192,
    'secp224r1': P224,
    'secp256r1': P256,
    'secp384r1': P384,
    'secp521r1': P521,
    'secp192k1': secp192k1,
    'secp224k1': secp224k1,
    'secp256k1': secp256k1,
    'brainpoolP160r1': brainpoolP160r1,
    'brainpoolP192r1': brainpoolP192r1,
    'brainpoolP224r1': brainpoolP224r1,
    'brainpoolP256r1': brainpoolP256r1,
    'brainpoolP320r1': brainpoolP320r1,
    'brainpoolP384r1': brainpoolP384r1,
    'brainpoolP512r1': brainpoolP512r1
}
