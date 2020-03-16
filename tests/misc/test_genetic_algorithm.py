from samson.auxiliary.genetic_algorithm import GeneticAlgorithm
from samson.analysis.general import str_hamming_distance
from samson.utilities.bytes import Bytes
import random
import string
import unittest


class GeneticAlgorithmTestCase(unittest.TestCase):
    def test_evolve_shakespeare(self):
        valid_chars = string.ascii_letters + ' .,\n\':'

        hamlet_excerpt = """To be or not to be, that is the question:
Whether 'tis nobler in the mind to suffer
The slings and arrows of outrageous Fortune,
Or to take arms against a sea of troubles
And by opposing end them. To die, to sleep"""


        def init_func(num):
            return [random.choice(valid_chars) * len(hamlet_excerpt) for _ in range(num)]


        def obj_func(pop):
            for individual in pop:
                individual.fitness = str_hamming_distance(individual.state, hamlet_excerpt)


        def crossover_func(parents):
            if Bytes.random(1).int() < 32:
                crossover_idx = Bytes.random(1).int() % len(hamlet_excerpt)
                ret = parents[0].state[:crossover_idx] + parents[1].state[crossover_idx:]
            else:
                ret = parents[0].state
            return ret


        def mutation_func(individual):
            if Bytes.random(1).int() < 32:
                mutation_idx = Bytes.random(1).int() % len(hamlet_excerpt)
                mutation = random.choice(valid_chars)
                individual.state = individual.state[:mutation_idx] + mutation + individual.state[mutation_idx+1:]

            return individual



        ga = GeneticAlgorithm(init_func, obj_func, crossover_func, mutation_func, 100, 10, 2, maximize=False, num_immigrants=2, minimum_convergence=0)
        result = ga.run(15000)
        self.assertEqual(result.solution.state, hamlet_excerpt)
