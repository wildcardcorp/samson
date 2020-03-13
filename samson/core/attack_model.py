from enum import Enum

class AttackModel(Enum):
    CIPHERTEXT_ONLY  = 0
    KNOWN_PLAINTEXT  = 1
    CHOSEN_PLAINTEXT = 2
    ADAPTIVE_CHOSEN_PLAINTEXT = 3
    CHOSEN_CIPHERTEXT = 4
    ADAPTIVE_CHOSEN_CIPHERTEXT = 5


    def implies(self, other):
        implications = {
            AttackModel.ADAPTIVE_CHOSEN_CIPHERTEXT: AttackModel.CHOSEN_CIPHERTEXT,
            AttackModel.CHOSEN_CIPHERTEXT: AttackModel.KNOWN_PLAINTEXT,
            AttackModel.ADAPTIVE_CHOSEN_PLAINTEXT: AttackModel.CHOSEN_PLAINTEXT,
            AttackModel.CHOSEN_PLAINTEXT: AttackModel.KNOWN_PLAINTEXT,
            AttackModel.KNOWN_PLAINTEXT: AttackModel.CIPHERTEXT_ONLY
        }

        curr = self
        while curr in implications:
            curr = implications[curr]

            if curr == other:
                return True

        return self == other
