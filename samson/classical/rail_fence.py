# https://stackoverflow.com/questions/14519227/rail-fence-cipher-looking-for-a-better-solution
class RailFence(object):
    """
    Zigzag transposition cipher whose construction resembles a rail fence.
    """

    def __init__(self, num_rails: int):
        """
        Parameters:
            num_rails (int): Number of "fence rails" to encrypt/decrypt over. This is effectively the key.
        """
        self.num_rails = num_rails



    def _fence(self, in_list):
        fence = [[None] * len(in_list) for n in range(self.num_rails)]
        rails = list(range(self.num_rails - 1)) + list(range(self.num_rails - 1, 0, -1))

        for n, x in enumerate(in_list):
            fence[rails[n % len(rails)]][n] = x

        return [c for rail in fence for c in rail if c is not None]



    def encrypt(self, plaintext: str) -> str:
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext (str): String to be encrypted.
        
        Returns:
            str: Resulting ciphertext.
        """
        return ''.join(self._fence(plaintext))


    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypts `ciphertext`.

        Parameters:
            ciphertext (str): Stringt to be decrypted.
        
        Returns:
            str: Resulting plaintext.
        """
        enc_pos = self._fence(range(len(ciphertext)))
        return ''.join([ciphertext[enc_pos.index(i)] for i in range(len(ciphertext))])
