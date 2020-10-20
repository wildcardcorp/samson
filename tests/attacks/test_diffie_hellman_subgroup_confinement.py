#!/usr/bin/python3
from samson.attacks.diffie_hellman_subgroup_confinement_attack import DiffieHellmanSubgroupConfinementAttack
from samson.utilities.bytes import Bytes
from samson.protocols.diffie_hellman import DiffieHellman
from samson.oracles.oracle import Oracle
from samson.hashes.sha2 import SHA256
from samson.macs.hmac import HMAC
import unittest


class DiffieHellmanSubgroupConfinementAttackTestCase(unittest.TestCase):
    def _run_test(self, p, g, q):
        m       = b"crazy flamboyant for the rap enjoyment"
        sha256  = SHA256()
        bob_key = DiffieHellman(p=p, g=g, q=q)

        def oracle_func(h, r):
            K    = bob_key.derive_key(h)
            hmac = HMAC(key=Bytes.wrap(K), hash_obj=sha256)
            mac  = hmac.generate(m)

            eve_hmac = HMAC(key=Bytes(r), hash_obj=sha256)

            return eve_hmac.generate(m) == mac

        oracle        = Oracle(oracle_func)
        dhsgc         = DiffieHellmanSubgroupConfinementAttack(oracle, p, g, order=q)
        recovered_key = dhsgc.execute(bob_key.get_challenge())

        self.assertEqual(recovered_key, bob_key.key)


    def test_two_phase(self):
        p = 11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623
        q = 335062023296420808191071248367701059461
        g = 622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357

        self._run_test(p, g, q)


    def test_one_phase(self):
        p = 7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771
        g = 4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143
        q = 236234353446506858198510045061214171961

        self._run_test(p, g, q)
