from math import log10
import os

# http://practicalcryptography.com/cryptanalysis/text-characterisation/word-statistics-fitness-measure/
class ViterbiDecoder(object):
    def __init__(self):
        ''' load a file containing ngrams and counts, calculate log probabilities '''
        self.Pw = {}
        with open(os.path.join(os.path.dirname(__file__), 'count_1w.txt'), 'r') as f:
            for line in f.readlines():
                key,count = line.split('\t') 
                self.Pw[key.upper()] = self.Pw.get(key.upper(), 0) + int(count)

        self.N = 1024908267229 ## Number of tokens

        # Calculate first order log probabilities
        for key in self.Pw.keys():
            self.Pw[key] = log10(float(self.Pw[key])/self.N)

        # Get second order word model 
        self.Pw2 = {}
        with open(os.path.join(os.path.dirname(__file__), 'count_2w.txt'), 'r') as f:
            for line in f.readlines():
                key,count = line.split('\t') 
                self.Pw2[key.upper()] = self.Pw2.get(key.upper(), 0) + int(count)

        # Calculate second order log probabilities
        for key in self.Pw2.keys():
            word1,_word2 = key.split()
            if word1 not in self.Pw: 
                self.Pw2[key] = log10(float(self.Pw2[key])/self.N)
            else: 
                self.Pw2[key] = log10(float(self.Pw2[key])/self.N) - self.Pw[word1]

        # Precalculate the probabilities we assign to words not in our dict, L is length of word
        self.unseen = [log10(10./(self.N * 10**L)) for L in range(50)]        
        
        
    # Conditional word probability    
    def cPw(self,word,prev='<UNK>'):
        if word not in self.Pw: 
            return self.unseen[len(word)]
        elif prev+' '+word not in self.Pw2: 
            return self.Pw[word]
        else: 
            return self.Pw2[prev+' '+word]
    

    def score(self,text,maxwordlen=20):
        prob = [[-99e99]*maxwordlen for _ in range(len(text))]
        strs = [['']*maxwordlen for _ in range(len(text))]

        for j in range(maxwordlen):
            prob[0][j] = self.cPw(text[:j+1])
            strs[0][j] = [text[:j+1]]

        for i in range(1,len(text)):
            for j in range(maxwordlen):
                if i+j+1 > len(text): break
                candidates = [(prob[i-k-1][k] + self.cPw(text[i:i+j+1],strs[i-k-1][k][-1]),
                               strs[i-k-1][k] + [text[i:i+j+1]] ) for k in range(min(i,maxwordlen))]

                prob[i][j], strs[i][j] = max(candidates)
                
        ends = [(prob[-i-1][i],strs[-i-1][i]) for i in range(min(len(text),maxwordlen))]
        return max(ends)