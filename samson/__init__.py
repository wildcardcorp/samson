from samson.analyzers import *
from samson.attacks import *
from samson.auxiliary import *
from samson.block_ciphers import *
from samson.block_ciphers.modes import *
from samson.classical import *
from samson.constructions import *
from samson.hashes import *
from samson.kdfs import *
from samson.macs import *
from samson.oracles import *
from samson.padding import *
from samson.prngs import *
from samson.protocols import *
from samson.publickey import *
from samson.stream_ciphers import *
from samson.utilities import *


import os

def _version():
    with open(os.path.join(os.path.dirname(__file__), '../VERSION')) as version_file:
        version = version_file.read().strip()
    
    return version


VERSION = _version()