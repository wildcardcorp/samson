from samson.utilities.math import mod_inv

class AffineCipher(object):
    """
    Monoalphabetic substitution of the form `(ax + b) mod m`.

    The Caesar cipher is an AffineCipher with a=1.
    """

    def __init__(self, a: int, b: int, alphabet: str='ABCDEFGHIJKLMNOPQRSTUVWXYZ ,.'):
        """
        Parameters:
            a        (int): Multiplier.
            b        (int): Linear shift.
            alphabet (str): Alphabet (in order) to encrypt over. Input must also be in this alphabet.
        """
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


    def encrypt(self, plaintext: str) -> str:
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext (str): String to be encrypted.
        
        Returns:
            str: Resulting ciphertext.
        """
        primitive_len = len(self.alphabet[0])

        ciphertext = ''
        for i in range(0, len(plaintext), primitive_len):
            curr_symbol = plaintext[i:i + primitive_len]

            if curr_symbol in self.char_map:
                ciphertext += self.char_map[curr_symbol]
            else:
                ciphertext += curr_symbol

        return ciphertext


    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypts `ciphertext`.

        Parameters:
            ciphertext (str): Stringt to be decrypted.
        
        Returns:
            str: Resulting plaintext.
        """
        primitive_len = len(self.alphabet[0])

        plaintext = ''
        for i in range(0, len(ciphertext), primitive_len):
            curr_symbol = ciphertext[i:i + primitive_len]

            if curr_symbol in self.inv_char_map:
                plaintext += self.inv_char_map[curr_symbol]
            else:
                plaintext += curr_symbol

        return plaintext
