from samson.utilities.math import mod_inv

class AffineCipher(object):
    def __init__(self, a, b, alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ ,.'):
        self.a = a
        self.b = b
        self.alphabet = alphabet

        self.char_map = {}
        for i in range(len(alphabet)):
            self.char_map[alphabet[i]] = alphabet[(a*i+b)%len(alphabet)]


        inv_a = mod_inv(a, len(alphabet))
        self.inv_char_map = {}
        for i in range(len(alphabet)):
            self.inv_char_map[alphabet[i]] = alphabet[(inv_a*(i-b))%len(alphabet)]


    def __repr__(self):
        return "<Affine: a={}, b={}, alphabet={}>".format(self.a, self.b, self.alphabet)

    def __str__(self):
        return self.__repr__()


    def encrypt(self, plaintext):
        primitive_len = len(self.alphabet[0])
        return ''.join([self.char_map[plaintext[i:i + primitive_len]] for i in range(0, len(plaintext), primitive_len)])


    def decrypt(self, ciphertext):
        primitive_len = len(self.alphabet[0])
        return ''.join([self.inv_char_map[ciphertext[i:i + primitive_len]] for i in range(0, len(ciphertext), primitive_len)])