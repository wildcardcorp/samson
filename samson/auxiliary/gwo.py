import numpy as np
import math
from copy import deepcopy
from types import FunctionType


class GreyWolfOptimizer:
  """
  Metaheuristic swarm-optmization algorithm.

>>> bRange = np.matrix([[0, 1],
... [-1, 1],
... [-1, 1],
... [-1, 1],
... [-1, 1]])

>>> gwo = GreyWolfOptimizer(200, 150, bRange, 0.01, oFunc)
>>> gwo.run()
  """

  def __init__(self, nWolves: int, nIters: int, boundsMat: np.ndarray, minConv: float, objFunc: FunctionType):
    """
    Parameters:
      nWolves             (int): Number of 'wolves' to spawn.
      nIters              (int): Number of iterations to run.
      boundsMat (numpy.ndarray): `p`x2 boundary matrix where `p` is the number of parameters.
      minConv           (float): Minminum convergence limit for early-out optimization.
      objFunc            (func): The objective function to *minimize*.
                                 NOTE: objFunc takes in wolf matrix
                                 and outputs cost vector of (nWolves, 1).
                                 This vector MUST be in the same order.
    """
    self.numWolves = nWolves
    self.maxIt = nIters
    self.wolves = np.zeros((0, boundsMat.shape[0] + 1))
    self.objFunc = objFunc
    self.boundaries = boundsMat
    self.bestWolves = np.zeros((0, boundsMat.shape[0] + 1))
    self.minConv = minConv

    numParams = boundsMat.shape[0]


    # Randomly initialize all wolves
    for w in range(self.numWolves):
      # Initialize wolf and add one to the wolf vector to hold cost
      wolf = np.zeros((1, numParams + 1))

      # Select random values within the boundaries
      for p in range(numParams):
        wolf[0][p] = np.random.uniform(self.boundaries[p, 0], self.boundaries[p, 1])

      self.wolves = np.concatenate((self.wolves, wolf))



  def run(self):
    """
    Runs the optimizer.

    Returns:
      int: Number of iterations ran. (NOTE: Solutions stored in `bestWolves`.)
    """
    numParams = self.wolves.shape[1] - 1
    min = np.transpose(self.boundaries[:, :1])
    max = np.transpose(self.boundaries[:, 1:2])

    last_top = 0.0
    max_conv_sample = 15
    curr_conv_sample = 0

    for i in range(self.maxIt):

      # Initialize variables
      a = 2 * (1 - (i ** 2 / self.maxIt ** 2))
      C = 2 * np.random.uniform(0, 1, (3 * self.numWolves, numParams))
      A = 2 * a * np.random.uniform(0, 1, (3 * self.numWolves, numParams)) - a

      # Calculate cost for each wolf
      self.wolves[:, numParams:] = self.objFunc(self.wolves)

      # Sort by best wolves using the cost column (last)
      self.wolves = np.array(self.wolves)
      self.wolves = self.wolves[self.wolves[:, numParams].argsort()]

      # Take top 3 wolves, don't take cost column
      topWolves = self.wolves[:3, :-1]
      topWolvesCost = self.wolves[:3]
      best_solution_cost = deepcopy(topWolvesCost[0, numParams:])
      self.bestWolves = np.concatenate((self.bestWolves, topWolvesCost[:1]))


      for w in range(self.numWolves):

        # Take every self.numWolves-th vector from matrices C and A
        currC = C[w::self.numWolves]
        currA = A[w::self.numWolves]

        # Repeat wolf w for each topWolf, so we can do a clean
        # subtraction (don't take cost column)
        currWolfMat = np.repeat(self.wolves[w, :-1].reshape(1, numParams), 3, axis=0)

        # Calculate Distance matrix
        D = np.absolute(np.multiply(topWolves, currC) - currWolfMat)

        currXs = topWolves - np.multiply(currA, D)

        # Take average as new solution
        mean = np.mean(currXs, axis=0)

        # Keep within boundaries
        boundsCheckedWolf = np.minimum(np.maximum(mean, min), max)
        self.wolves[w] = np.array(np.append(boundsCheckedWolf.tolist(), 0))

      self.wolves = np.concatenate((self.wolves[3:], topWolvesCost))

      # Determines whether we're making much progress
      # If not, we should break
      if last_top - best_solution_cost < self.minConv:
          curr_conv_sample += 1
      else:
          curr_conv_sample = 0

      if curr_conv_sample == max_conv_sample:
          return i

      last_top = best_solution_cost


    # Sort wolves
    self.bestWolves = self.bestWolves[self.bestWolves[:, numParams].argsort()]
    return i


# Simple test cost func
def oFunc(mat):
  return (mat[:, 0:1] * 3.0) + (mat[:, 1:2] * -2.0) + (mat[:, 2:3] * 0.75) + (mat[:, 3:4] * 10.0) + (mat[:, 4:5] * -0.8)


# More complex test case
def UF1(x):
  x = np.transpose(x)
  dim = x.shape[0]
  num = x.shape[1]
  tmp = np.zeros((dim, num))

  tiled = np.tile(x[0, :], dim - 1).reshape(dim - 1, num)

  temp1 = np.multiply(tiled, 6 * math.pi)
  temp2 = math.pi / dim * np.repeat(np.array(range(2, dim + 1)), num).reshape(dim - 1, num)


  tmp[1:dim, :] = (x[1:dim, :] - np.sin(temp1 + temp2)) ** 2

  evens = tmp[2:dim:2, :]
  odds = tmp[1:dim:2, :]

  if(evens.shape[0] > 1):
    tmp1 = np.sum(evens, axis=0)
  else:
    tmp1 = np.sum(evens)


  if(odds.shape[0] > 1):
    tmp2 = np.sum(odds, axis=0)
  else:
    tmp2 = np.sum(odds)


  y = np.zeros((2, num))

  y[0, :] = x[0, :] + 2.0 * tmp1 / len(range(2, dim, 2))
  y[1, :] = 1.0 - np.sqrt(x[0, :]) + 2.0 * tmp2 / len(range(1, dim, 2))
  return np.sum(y, axis=0).reshape(num, 1)
