from samson.math.general import gcd, mod_inv, is_power_of_two, is_prime, is_primitive_root
from samson.math.factorization.general import factor as factorint
from samson.math.matrix import Matrix
from samson.utilities.exceptions import SearchspaceExhaustedException
from samson.utilities.runtime import RUNTIME
import functools


class LCG(object):
    """
    Linear congruential generator of the form `(a*X + c) mod m`.
    """

    def __init__(self, X: int, a: int, c: int, m: int, trunc: int=0):
        """
        Parameters:
            X     (int): Initial state.
            a     (int): Multiplier.
            c     (int): Increment.
            m     (int): Modulus.
            trunc (int): Number of bits to truncate on output
        """
        self.a = a
        self.c = c
        self.m = m
        self.trunc = trunc

        self.X = X


    def __repr__(self):
        return f"<LCG: X={self.X}, a={self.a}, c={self.c}, m={self.m}, trunc={self.trunc}>"

    def __str__(self):
        return self.__repr__()


    def generate(self) -> int:
        """
        Generates the next pseudorandom output.

        Returns:
            int: Next pseudorandom output.
        """
        self.X = (self.a * self.X + self.c) % self.m
        return self.X >> self.trunc


    def check_full_period(self) -> bool:
        """
        Checks whether the LCG will achieve a full period with its current parameters.

        Returns:
            bool: Whether or not it will acheive a full period.
        
        References:
            https://en.wikipedia.org/wiki/Linear_congruential_generator#Period_length
        """
        # Technically, this achieves m-1
        if is_prime(self.m) and self.c == 0 and is_primitive_root(self.a, self.m):
            return True

        # Maximially m/4
        elif is_power_of_two(self.m) and self.c == 0:
            return False

        else:
            # 1. m and c are relatively prime
            relatively_prime = gcd(self.m, self.c) == 1

            # 2. a-1 is divisible by all prime factors of m
            factors = [factor for factor in factorint(self.m)]
            divisible_by_all_factors = all([((self.a - 1) % factor) == 0 for factor in factors])

            # 3. a-1 is divisible by 4 if m is divisible by 4
            divisible_by_four = True
            if self.m % 4 == 0:
                divisible_by_four = (self.a - 1) % 4 == 0

            return relatively_prime and divisible_by_all_factors and divisible_by_four



    def __getattribute__(self, name):
        from functools import partial

        if name == "crack":
            if self.trunc:
                return partial(LCG.crack_truncated, outputs_to_predict=None, multiplier=self.a, increment=self.c, modulus=self.m, trunc_amount=self.trunc)
            else:
                return partial(LCG.crack, multiplier=self.a, increment=self.c, modulus=self.m)
        else:
            return object.__getattribute__(self, name)



    @staticmethod
    def crack(states: list, multiplier: int=None, increment: int=None, modulus: int=None, sanity_check: bool=True):
        """
        Given a few full states (probably under ten) and any (or even none) of the parameters of an LCG, returns a replica LCG.

        Parameters:
            states       (list): List of full-state outputs (in order).
            multiplier    (int): (Optional) The LCG's multiplier.
            increment     (int): (Optional) The LCG's increment.
            modulus       (int): (Optional) The LCG's modulus.
            sanity_check (bool): Whether to tests the generated LCG against the provided states.
        
        Returns:
            LCG: Replica LCG that predicts all future outputs of the original.
        
        References:
            https://tailcall.net/blog/cracking-randomness-lcgs/
        """
        if not modulus:
            diffs = [state1 - state0 for state0, state1 in zip(states, states[1:])]
            congruences = [t2*t0 - t1*t1 for t0, t1, t2 in zip(diffs, diffs[1:], diffs[2:])]
            modulus = abs(functools.reduce(gcd, congruences))


        if not multiplier:
            multiplier = (states[2] - states[1]) * mod_inv(states[1] - states[0], modulus) % modulus


        if not increment:
            increment = (states[1] - states[0] * multiplier) % modulus


        # Sanity test
        lcg = LCG(states[0], multiplier, increment, modulus)
        num_tests = min(3, len(states) - 1)

        if sanity_check and [lcg.generate() for _ in range(num_tests)] != states[1:1 + num_tests]:
            raise RuntimeError("Generated LCG does not match 'states'. Are you sure this came from an untruncated LCG?")

        return LCG(states[-1], multiplier, increment, modulus)


    @classmethod
    @RUNTIME.report
    def crack_truncated(cls: object, outputs: list, outputs_to_predict: list, multiplier: int, increment: int, modulus: int, trunc_amount: int) -> 'LCG':
        """
        Given a decent number of truncated states (about 200 when there's only 3-bit outputs), returns a replica LCG.

        Parameters:
            outputs            (list): List of truncated-state outputs (in order).
            outputs_to_predict (list): Next few outputs to compare against. Accuracy/number of samples trade-off.
            multiplier          (int): The LCG's multiplier.
            increment           (int): The LCG's increment.
            modulus             (int): The LCG's modulus.

        Returns:
            LCG: Replica LCG that predicts all future outputs of the original.

        References:
            https://github.com/mariuslp/PCG_attack
            "Reconstructing Truncated Integer Variables Satisfying Linear Congruences" (https://www.math.cmu.edu/~af1p/Texfiles/RECONTRUNC.pdf)
        """
        if not outputs_to_predict:
            outputs_to_predict = outputs[-2:]
            outputs = outputs[:-2]

        # Trivial case
        if increment == 0:
            computed_seed = LCG.solve_tlcg(outputs + outputs_to_predict, multiplier, modulus, trunc_amount)

            # Here we take the second to last seed since our implementation edits the state BEFORE it returns
            return LCG((multiplier * computed_seed[-2]) % modulus, multiplier, increment, modulus, trunc=trunc_amount)

        else:
            diffs      = [o2 - o1 for o1, o2 in zip(outputs, outputs[1:])]
            seed_diffs = LCG.solve_tlcg(diffs, multiplier, modulus, trunc_amount)
            seed_diffs = [int(seed_diff) % modulus for row in seed_diffs for seed_diff in row]

            # Bruteforce low bits
            for z in RUNTIME.report_progress(range(2 ** trunc_amount), desc='Seedspace searched', unit='seeds'):
                x_0 = (outputs[0] << trunc_amount) + z
                x_1 = (seed_diffs[0] + x_0) % modulus
                computed_c = (x_1 - multiplier * x_0) % modulus

                computed_x_2 = (multiplier * x_1 + computed_c) % modulus
                actual_x_2   = (seed_diffs[1] + x_1) % modulus

                if computed_x_2 == actual_x_2:
                    computed_seeds = [x_0]

                    for diff in seed_diffs:
                        computed_seeds.append((diff + computed_seeds[-1]) % modulus)


                    # It's possible to find a spectrum of nearly-equivalent LCGs.
                    # The accuracy of `predicted_lcg` is dependent on the size of `outputs_to_predict` and the
                    # parameters of the LCG.
                    predicted_seed = (multiplier * computed_seeds[-2] + computed_c) % modulus
                    predicted_lcg  = LCG(X=int(predicted_seed), a=multiplier, c=int(computed_c), m=modulus, trunc=trunc_amount)

                    if [predicted_lcg.generate() for _ in range(len(outputs_to_predict))] == outputs_to_predict:
                        return predicted_lcg

            raise SearchspaceExhaustedException('Seedspace exhausted')



    @staticmethod
    def solve_tlcg(outputs: list, multiplier: int, modulus: int, trunc_amount: int) -> Matrix:
        """
        Used internally by `crack_truncated`. Uses the LLL algorithm to find seed differentials.

        Parameters:
            outputs   (list): List of truncated-state outputs (in order).
            multiplier (int): The LCG's multiplier.
            increment  (int): The LCG's increment.
            modulus    (int): The LCG's modulus.
        
        Returns:
            Matrix: Seed differentials.
        """
        from samson.math.all import QQ

        # Initialize matrix `L`
        l_matrix = [[0 for _ in range(len(outputs))] for _ in range(len(outputs))]
        l_matrix[0][0] = modulus

        for i in range(1, len(outputs)):
            l_matrix[i][0] = multiplier ** i
            l_matrix[i][i] = -1


        l_matrix = Matrix(l_matrix)
        reduced_basis = l_matrix.LLL()

        # Construct and reduce
        y = Matrix([[2**trunc_amount * x % modulus for x in outputs]], QQ).T
        reduced_outputs = reduced_basis * y

        # Solve system
        c_prime = Matrix([[(round(float(x[0] / modulus)) * modulus) - x[0] for x in reduced_outputs]]).T
        z = reduced_basis.LUsolve(c_prime)

        return y + z
