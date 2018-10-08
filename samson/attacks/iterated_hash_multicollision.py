from math import ceil
import struct

class IteratedHashMulticollisionAttack(object):
    def __init__(self, hash_func):
        self.hash_func = hash_func
        self._collisions = {}


    def _find_collision(self, iv):
        hash_dict = {}

        for i in range(2**64):
            attempt = struct.pack('Q', i)
            digest = self.hash_func(iv, attempt)
            if digest in hash_dict:
                if (iv, digest) not in self._collisions:
                    print(i)
                    return (digest, [attempt, hash_dict[digest]])
            else:
                hash_dict[digest] = attempt

    
    def execute(self, iv, num):
        self._collisions = {}

        for _ in range(ceil(num / 2)):
            digest, inputs = self._find_collision(iv)
            key = (iv, digest)
            iv = digest
            
            if digest in self._collisions:
                self._collisions[key] = list(set(self._collisions[key] + inputs))
            else:
                self._collisions[key] = inputs
                
        return self._collisions