from samson.utilities.bytes import Bytes
from samson.math.symbols import Symbol
from samson.math.algebra.rings.integer_ring import ZZ
import os

CURR_DIR = os.path.dirname(os.path.abspath(__file__))


def parse_atkin(data: str):
    x = Symbol('x')
    y = Symbol('y')

    P = ZZ[x, y]
    p = P.zero
    for line in data.strip().split('\n'):
        xp, yp, c = [int(c) for c in line.strip().split()]
        p += x**xp*y**yp*c
    
    return p



# https://www.i2m.univ-amu.fr/perso/david.kohel/dbs/files/PolMod_Atk.tgz
class AtkinDB(object):
    def __init__(self) -> None:
        self.db = {}


    def __getitem__(self, idx):
        if idx not in self.db:
            data = Bytes.read_file(f'{CURR_DIR}/atkin_db/pol.{str(idx).zfill(3)}.dbz.out').decode()
            self.db[idx] = parse_atkin(data)

        return self.db[idx]
