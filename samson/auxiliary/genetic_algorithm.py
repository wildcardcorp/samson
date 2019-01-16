from enum import Enum
from types import FunctionType
from samson.utilities.runtime import RUNTIME
import random


class Chromosome(object):
    """
    Represents a Chromosome. Used by GeneticAlgorithm to keep state.
    """

    def __init__(self, state: object):
        """
        Parameters:
            state (object): The "DNA" of the organism. Can be anything.
        """
        self.state = state
        self.fitness = 0


    def __repr__(self):
        return f"<Chromosome: state={self.state}, fitness={self.fitness}>"

    def __str__(self):
        return self.__repr__()


class TerminationReason(Enum):
    MAX_ITERATION_REACHED = 0
    MINIMUM_CONVERGENCE_UNSATISFIED = 1
    GLOBAL_OPTIMA_REACHED = 2


class OptimizationResult(object):
    """
    Encapsulates finished-state information for optimization algorithms.
    """

    def __init__(self, solution: object, iteration: int, termination_reason: TerminationReason):
        """
        Parameters:
            solution                      (object): Best solution from the optimization algorithm.
            iteration                        (int): Iteration stopped at.
            termination_reason (TerminationReason): Reason for execution termination.
        """
        self.solution = solution
        self.iteration = iteration
        self.termination_reason = termination_reason


    def __repr__(self):
        return f"<OptimizationResult: solution={self.solution}, iteration={self.iteration}, termination_reason={self.termination_reason}>"

    def __str__(self):
        return self.__repr__()


# https://en.wikipedia.org/wiki/Genetic_algorithm
class GeneticAlgorithm(object):
    """
    Highly configurable genetic algorithm implementation. Bring-your-own functions.
    """

    def __init__(self,
            initialization_func: FunctionType,
            obj_func: FunctionType,
            crossover_func: FunctionType,
            mutation_func: FunctionType,
            population_size: int,
            parent_pool_size: int,
            num_parents: int,
            maximize: bool=True,
            elitism: bool=True,
            num_immigrants: int=0,
            minimum_convergence: float=1e-6,
            min_conv_tolerance: int=5,
            convergence_granularity: int=1000000):
        """
        Parameters:
            initialization_func    (func): Takes in an int and initializes that many population members.
            obj_func               (func): Takes in a list of Chromosomes changes their `fitness` value.
            crossover_func         (func): Takes in a list of parents and possibly performs crossover. Returns a "child" state.
            mutation_func          (func): Takes in a Chromosome and possibly mutates it.
            population_size         (int): Size of the population.
            parent_pool_size        (int): Size of the parent pool to breed the next generation.
            num_parents             (int): Number of parents to produce a child (i.e. n-way crossover).
            maximize               (bool): True to maximize the objective function, False to minimize it.
            elitism                (bool): Whether or not to insert the best solutions of the last generation into the next.
            num_immigrants          (int): Number of "immigrants". Immigrants are additional parents created using `initialization_func`.
            minimum_convergence   (float): Minimum convergence differential between generations before ticking the `min_conv_counter`.
            min_conv_tolerance      (int): Number of generations not satisfying minimum convergence before terminating.
            convergence_granularity (int): Granularity for comparing minimum convergence and fitness. Internally, `minimum_convergence` is discretized to allow for multi-precision integer fitness scores.
        """
        self.initialization_func = initialization_func
        self.obj_func = obj_func
        self.crossover_func = crossover_func
        self.mutation_func = mutation_func

        self.parent_pool_size = parent_pool_size
        self.num_parents = num_parents
        self.population_size = population_size
        self.population = [Chromosome(individual) for individual in self.initialization_func(self.population_size)]

        self.maximize = maximize
        self.elitism = elitism
        self.num_immigrants = num_immigrants
        self.minimum_convergence = minimum_convergence
        self.min_conv_tolerance = min_conv_tolerance
        self.convergence_granularity = convergence_granularity


    def __repr__(self):
        return f"<GeneticAlgorithm: parent_pool_size={self.parent_pool_size}, num_parents={self.num_parents}, population_size={self.population_size}, maximize={self.maximize}, elitism={self.elitism}, num_immigrants={self.num_immigrants}, minimum_convergence={self.minimum_convergence}, min_conv_tolerance={self.min_conv_tolerance}>"

    def __str__(self):
        return self.__repr__()


    @RUNTIME.report
    def run(self, generations: int) -> OptimizationResult:
        min_conv_counter = 0
        current_best = (not self.maximize) * 2**8192
        termination_reason = TerminationReason.MAX_ITERATION_REACHED
        granularized_minimum_convergence = self.convergence_granularity * self.minimum_convergence

        for iteration in RUNTIME.report_progress(range(generations), desc='Generations', unit='gens'):
            # 1) Measure
            self.obj_func(self.population)

            # 2) Select
            parent_pool = sorted(self.population, key=lambda chromo: chromo.fitness, reverse=self.maximize)[:self.parent_pool_size]

            # Test for minimum convergence heuristic
            if abs(parent_pool[0].fitness - current_best) // (current_best * self.convergence_granularity) < granularized_minimum_convergence:
                if min_conv_counter < self.min_conv_tolerance:
                    min_conv_counter += 1
                else:
                    termination_reason = TerminationReason.MINIMUM_CONVERGENCE_UNSATISFIED
                    break
            else:
                current_best = parent_pool[0].fitness
                min_conv_counter = 0


            if not self.maximize and not current_best:
                termination_reason = TerminationReason.GLOBAL_OPTIMA_REACHED
                break

            next_population = []

            # Elitism
            if self.elitism:
                next_population.extend(parent_pool)

            # Immigration
            parent_pool.extend([Chromosome(individual) for individual in self.initialization_func(self.num_immigrants)])

            # Breeding
            while len(next_population) < self.population_size:
                parents = random.sample(parent_pool, k=self.num_parents)

                # 3) Crossover
                individual = Chromosome(self.crossover_func(parents))

                # 4) Mutate
                individual = self.mutation_func(individual)

                next_population.append(individual)


            self.population = next_population

        self.obj_func(self.population)

        return OptimizationResult(sorted(self.population, key=lambda chromo: chromo.fitness, reverse=self.maximize)[0], iteration, termination_reason)
