from z3 import BitVecs, Solver, LShR, Bool, Implies, sat, RotateLeft
from samson.utilities.exceptions import NoSolutionException
from inspect import isclass
import random


class IterativePRNG(object):
    """
    Base class for PRNGs that iterate over fixed-size state.
    """

    def generate(self) -> int:
        """
        Generates the next pseudorandom output.

        Returns:
            int: Next pseudorandom output.
        """
        state, result = self.gen_func(*self.state)
        self.state = state
        return result


    def crack(self, outputs: list) -> 'IterativePRNG':
        """
        Cracks the PRNG's internal state using `outputs`.

        Parameters:
            outputs (list): Observed, sequential outputs.
        
        Returns:
            IterativePRNG: Cracked IterativePRNG of the subclass' class.
        """
        state_vecs = BitVecs(' '.join([f'ostate{i}' for i in range(self.STATE_SIZE)]), self.NATIVE_BITS)
        sym_states = state_vecs

        solver = Solver()
        conditions = []

        for output in outputs:
            sym_states, calc = self.gen_func(*sym_states, SHFT_L=lambda x, n: x << n, SHFT_R=LShR, RotateLeft=RotateLeft)

            condition = Bool('c%d' % int(random.random()))
            solver.add(Implies(condition, calc == int(output)))
            conditions += [condition]

        if solver.check(conditions) == sat:
            model = solver.model()
            params = [model[vec].as_long() for vec in state_vecs]

            if isclass(self):
                prng = self(params)
            else:
                prng = self.__class__(params)

            [prng.generate() for _ in outputs]
            return prng
        else:
            raise NoSolutionException('Model not satisfiable.')
