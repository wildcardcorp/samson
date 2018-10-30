from samson.utilities.math import gcd, mod_inv, lll, is_power_of_two
from sympy.matrices import Matrix
from sympy import isprime
from sympy.ntheory import factorint
from sympy.ntheory.residue_ntheory import is_primitive_root
import functools


class LCG(object):
    def __init__(self, X, a, c, m):
        self.a = a
        self.c = c
        self.m = m

        self.X = X


    def __repr__(self):
        return f"<LCG: X={self.X}, a={self.a}, c={self.c}, m={self.m}>"


    def __str__(self):
        return self.__repr__()
        

    def generate(self):
        self.X = (self.a * self.X + self.c) % self.m
        return self.X

    
    # https://en.wikipedia.org/wiki/Linear_congruential_generator#Period_length
    def check_full_period(self):
        if isprime(self.m) and self.c == 0 and is_primitive_root(self.a, self.m):
            return True
        elif is_power_of_two(self.m) and self.c == 0:
            return False
        else:
            divisible_by_four = True
            if self.m % 4 == 0:
                divisible_by_four = (self.a - 1) % 4 == 0

            factors = [factor for factor, count in factorint(self.m).items()]
            divisible_by_all_factors = all([((self.a - 1) % factor) == 0 for factor in factors])
            return gcd(self.m, self.c) == 1 and divisible_by_four and divisible_by_all_factors



    # https://tailcall.net/blog/cracking-randomness-lcgs/
    @staticmethod
    def crack(states, multiplier=None, increment=None, modulus=None):
        if not modulus:
            diffs = [state1 - state0 for state0, state1 in zip(states, states[1:])]
            congruences = [t2*t0 - t1*t1 for t0, t1, t2 in zip(diffs, diffs[1:], diffs[2:])]
            modulus = abs(functools.reduce(gcd, congruences))

        
        if not multiplier:
            multiplier = (states[2] - states[1]) * mod_inv(states[1] - states[0], modulus) % modulus


        if not increment:
            increment = (states[1] - states[0] * multiplier) % modulus

        return LCG(states[-1], multiplier, increment, modulus)
    
    

    # Reference: https://github.com/mariuslp/PCG_attack
    # Reference: https://www.math.cmu.edu/~af1p/Texfiles/RECONTRUNC.pdf
    # ^^ "Reconstructing Truncated Integer Variables Satisfying Linear Congruences"
    @staticmethod
    def crack_truncated(outputs, outputs_to_predict, multiplier, increment, modulus, trunc_amount):
        # Trivial case
        if increment == 0:
            computed_seed = LCG.solve_tlcg(outputs + outputs_to_predict, multiplier, modulus, trunc_amount)

            # Here we take the second to last seed since our implementation edits the state BEFORE it returns
            return LCG((multiplier * computed_seed[-2]) % modulus, multiplier, increment, modulus)

        else:
            diffs = [o2 - o1 for o1, o2 in zip(outputs, outputs[1:])]
            seed_diffs = LCG.solve_tlcg(diffs, multiplier, modulus, trunc_amount)
            seed_diffs = [seed_diff % modulus for seed_diff in seed_diffs]


            # Bruteforce low bits
            for z in range(2 ** trunc_amount):
                x_0 = (outputs[0] << trunc_amount) + z
                x_1 = (seed_diffs[0] + x_0) % modulus
                computed_c = (x_1 - multiplier * x_0) % modulus

                computed_x_2 = (multiplier * x_1 + computed_c) % modulus
                actual_x_2 = (seed_diffs[1] + x_1) % modulus

                if computed_x_2 == actual_x_2:
                    computed_seeds = [x_0]

                    for diff in seed_diffs:
                        computed_seeds.append((diff + computed_seeds[-1]) % modulus)
                    

                    # It's possible to find a spectrum of nearly-equivalent LCGs.
                    # The accuracy of `predicted_lcg` is dependent on the size of `outputs_to_predict` and the
                    # parameters of the LCG.
                    predicted_seed = (multiplier * computed_seeds[-2] + computed_c) % modulus
                    predicted_lcg = LCG(X=int(predicted_seed), a=multiplier, c=int(computed_c), m=modulus)

                    if [predicted_lcg.generate() >> trunc_amount for _ in range(len(outputs_to_predict))] == outputs_to_predict:
                        return predicted_lcg






    @staticmethod
    def solve_tlcg(outputs, multiplier, modulus, trunc_amount):
        # Initialize matrix `L`
        l_matrix = [[0 for _ in range(len(outputs))] for _ in range(len(outputs))]
        l_matrix[0][0] = modulus

        for i in range(1, len(outputs)):
            l_matrix[i][0] = multiplier ** i
            l_matrix[i][i] = -1


        l_matrix = Matrix(l_matrix)
        reduced_basis = lll([l_matrix.row(row) for row in range(l_matrix.rows)])

        # Construct and reduce `y` vector
        y = Matrix([2**trunc_amount * x % modulus for x in outputs])
        reduced_outputs = reduced_basis * y

        c_prime = Matrix([(round(x / modulus) * modulus) - x for x in reduced_outputs])
        z = Matrix(reduced_basis.LUsolve(c_prime))

        return y + z
