from samson.primitives.aes_ctr import AES_CTR
from samson.primitives.xor import decrypt
from samson.utilities import gen_rand_key
from samson.analyzers.english_analyzer import *
from samson.attacks.ctr_transposition_attack import CTRTranspositionAttack
from sklearn.tree import DecisionTreeClassifier
from sklearn.cross_validation import train_test_split
from sklearn.metrics import confusion_matrix
from sklearn.utils import shuffle
import pandas as pd
import base64
import struct
import pickle


block_size = 16
key = gen_rand_key(block_size)

def encrypt(secret):
    aes = AES_CTR(key, struct.pack('Q', 0))
    return aes.encrypt(secret)


with open('/home/donald/Git/samson/tests/test_ctr_transposition.txt') as f:
    secrets = [base64.b64decode(line.strip().encode()) for line in f.readlines()]

ciphertexts = [encrypt(secret) for secret in secrets]

analyzer = EnglishAnalyzer()

attack = CTRTranspositionAttack(analyzer, decrypt, block_size)
recovered_plaintexts, analyses = attack.execute(ciphertexts)

preprocessed = [analyzer.preprocess(analysis, secrets) for analysis in analyses]
preprocessed = [result for result in preprocessed if result != 0]

correct_preprocessed = [analyzer.preprocess(secret, secrets) for secret in secrets]

all_processed = shuffle(preprocessed + correct_preprocessed)

X = pd.DataFrame(all_processed, columns=['word_freq', 'alphabet_ratio', 'ascii_ratio', 'common_letters', 'common_words', 'first_letter_freq', 'bigrams'])
y = pd.DataFrame(all_processed, columns=['is_correct'])

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=0)

dcc = DecisionTreeClassifier(random_state = 2)
dcc.fit(X_train, y_train)

tn, fp, fn, tp = confusion_matrix(y_test.values, dcc.predict(X_test.values)).ravel()

print((tn, fp, fn, tp))

pickle.dumps(dcc)