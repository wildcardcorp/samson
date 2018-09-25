import string

# http://practicalcryptography.com/ciphers/playfair-cipher/
class Playfair(object):
    def __init__(self, key):
        if len(list(set(list(key)))) < len(key):
            raise Exception("Key cannot have duplicate characters")

        # Playfair combines 'i' and 'j'
        assert 'j' not in key

        for letter in string.ascii_lowercase:
            if letter not in key and letter != 'j':
                key += letter

        self.key = key


    def __repr__(self):
        return "<Playfair key={}>".format(self.key)



    def encrypt(self, plaintext):
        plaintext = plaintext.replace("j", "i")

        # Remove characters not in key
        for char in plaintext:
            if char not in self.key:
                plaintext = plaintext.replace(char, "")


        # Substitute duplicate letters with x
        for i in range(len(plaintext) - 1):
            if plaintext[i] == plaintext[i + 1]:
                plaintext[i + 1] = 'x'


        # If plaintext has an odd number of characters, add an 'x' to the end
        if len(plaintext) % 2 == 1:
            plaintext += 'x'
        

        ciphertext = ''
        for i in range(0, len(plaintext), 2):
            a, b = plaintext[i], plaintext[i + 1]
            a_loc, b_loc = self.key.index(a), self.key.index(b)

            a_row, a_col = a_loc // 5, a_loc % 5
            b_row, b_col = b_loc // 5, b_loc % 5

            if a_row != b_row and a_col != b_col:
                new_a = a_row * 5 + b_col
                new_b = b_row * 5 + a_col
            elif a_row == b_row:
                new_a = a_row + ((a_col + 1) % 5)
                new_b = a_row + ((b_col + 1) % 5)
            else:
                new_a = ((a_row + 1) % 5) * 5 + a_col
                new_b = ((b_row + 1) % 5) * 5 + a_col

            ciphertext += self.key[new_a] + self.key[new_b]
        return ciphertext



    def decrypt(self, ciphertext):
        plaintext = ''
        for i in range(0, len(ciphertext), 2):
            a, b = ciphertext[i], ciphertext[i + 1]
            a_loc, b_loc = self.key.index(a), self.key.index(b)

            a_row, a_col = a_loc // 5, a_loc % 5
            b_row, b_col = b_loc // 5, b_loc % 5

            if a_row != b_row and a_col != b_col:
                new_a = a_row * 5 + b_col
                new_b = b_row * 5 + a_col
            elif a_row == b_row:
                new_a = a_row + ((a_col - 1) % 5)
                new_b = a_row + ((b_col - 1) % 5)
            else:
                new_a = ((a_row - 1) % 5) * 5 + a_col
                new_b = ((b_row - 1) % 5) * 5 + a_col

            plaintext += self.key[new_a] + self.key[new_b]
        return plaintext