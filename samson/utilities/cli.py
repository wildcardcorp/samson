start_exec = """
from samson.all import *
x = Symbol('x')
y = Symbol('y')
z = Symbol('z')

import logging
logging.getLogger().setLevel(logging.WARNING)
logging.getLogger("samson").setLevel(logging.DEBUG)
logger = logging.getLogger("samson.repl")
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
    from traitlets.config import Config

    banner = f"""
{LOGO}
    v{VERSION} -- https://github.com/wildcardcorp/samson

Python {sys.version}
IPython {IPython.__version__}
"""

    conf = Config()
    conf.TerminalIPythonApp.display_banner = False
    conf.InteractiveShellApp.exec_lines = [
        start_exec,
        f'print("""{banner}""")'
    ]

    conf.InteractiveShell.confirm_exit = False
    conf.TerminalInteractiveShell.term_title_format = f"samson v{VERSION}"

    IPython.start_ipython(config=conf)


from samson.hashes.all import MD4, MD5, BLAKE2b, BLAKE2s, Keccak, RIPEMD160, SHA1, SHA224, SHA256, SHA384, SHA512, SHA3, Whirlpool
from samson.public_key.all import RSA, DSA, ECDSA, EdDSA
from samson.math.algebra.curves.named import EdwardsCurve25519, EdwardsCurve448
from samson.encoding.general import PKIEncoding, PKIAutoParser
from samson.math.algebra.curves.named import P192, P224, P256, P384, P521, secp192k1, secp224k1, secp256k1, brainpoolP160r1, brainpoolP192r1, brainpoolP224r1, brainpoolP256r1, brainpoolP320r1, brainpoolP384r1, brainpoolP512r1

HASHES = {
    'blake2b': BLAKE2b,
    'blake2s': BLAKE2s,
    'keccak': Keccak,
    'md4': MD4,
    'md5': MD5,
    'ripemd160': RIPEMD160,
    'sha1': SHA1,
    'sha224': SHA224,
    'sha256': SHA256,
    'sha384': SHA384,
    'sha512': SHA512,
    'sha3_224': SHA3.K224,
    'sha3_256': SHA3.K256,
    'sha3_384': SHA3.K384,
    'sha3_512': SHA3.K512,
    'shake128': SHA3.SHAKE128,
    'shake256': SHA3.SHAKE256,
    'whirlpool': Whirlpool
}

PKI = {
    'rsa': RSA,
    'dsa': DSA,
    'ecdsa': ECDSA,
    'eddsa': EdDSA,
    'auto': PKIAutoParser
}


EC_CURVES = {curve.name.lower():curve for curve in [P192, P224, P256, P384, P521, secp192k1, secp224k1, secp256k1, brainpoolP160r1, brainpoolP192r1, brainpoolP224r1, brainpoolP256r1, brainpoolP320r1, brainpoolP384r1, brainpoolP512r1]}
EC_CURVES.update({
    'secp192r1': P192,
    'secp224r1': P224,
    'secp256r1': P256,
    'secp384r1': P384,
    'secp521r1': P521,
    'nistp192': P192,
    'nistp224': P224,
    'nistp256': P256,
    'nistp384': P384,
    'nistp521': P521
})

ED_CURVES = {
    'ed25519': EdwardsCurve25519,
    'ed448': EdwardsCurve448
}


ENCODING_MAPPING = {
    'JWK': PKIEncoding.JWK,
    'OPENSSH': PKIEncoding.OpenSSH,
    'PKCS1': PKIEncoding.PKCS1,
    'PKCS8': PKIEncoding.PKCS8,
    'SSH2': PKIEncoding.SSH2,
    'X509': PKIEncoding.X509,
    'X509_CERT': PKIEncoding.X509_CERT
}
