from samson.oracles.timing_oracle import TimingOracle, percentile_filter
from tqdm import tqdm
import string
import unittest

SECRET = 'abracadabra'

def vulnerable_func(attempt):
    for a, b in zip(attempt, SECRET):
        if a == b:
            # ~35ns
            [_ for _ in range(1)]
        else:
            break


class TimingOracleTestCase(unittest.TestCase):
    def test_hi_res(self):
        oracle = TimingOracle(vulnerable_func, filters=[lambda items: percentile_filter(0.1, items)])

        args = {'sample_size':80000}
        answer = ''
        for _ in tqdm(range(11)):
            results = [(char, oracle.get_timing(answer + char + 'z'*(10 - len(answer)), **args)) for char in string.ascii_lowercase]
            answer += sorted(results, key=lambda item: item[1][0], reverse=True)[0][0]


        self.assertEqual(answer, SECRET)
