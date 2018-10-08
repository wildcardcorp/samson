from samson.utilities.general import rand_bytes

class MarkovState(object):
    def __init__(self, count, probability, transitions):
        self.count = count
        self.probability = probability
        self.transitions = transitions


    def __repr__(self):
        return "<MarkovState: transitions={}, count={}, probability={}>".format(self.transitions.keys(), self.count, self.probability)

    def __str__(self):
        return self.__repr__()



    # Recursively turn counts into probabilities
    def calculate_chain_probs(self):
        total_count = sum([subchain.count for token, subchain in self.transitions.items()])

        for _token, subchain in self.transitions.items():
            subchain.probability = subchain.count / total_count
            subchain.calculate_chain_probs()



    def random_walk(self, distance):
        result = []
        if distance > 0:
            rand_num = int.from_bytes(rand_bytes(1), 'big')
            winning_probability = rand_num / 256
            
            prob_accumulator = 0.0

            for token, subchain in self.transitions.items():
                prob_accumulator += subchain.probability

                if prob_accumulator >= winning_probability:
                    result = [token] + subchain.random_walk(distance - 1)
                    break

        return result
