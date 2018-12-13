from samson.oracles.encryption_oracle import EncryptionOracle
from samson.utilities.bytes import Bytes


class XORBitflippingAttack(object):
    """
    Performs a plaintext manipulation attack.

    CTR/stream ciphers will XOR the keystream with the ciphertext to decrypt the data. By injecting known plaintext,
    we can recover that block's keystream and XOR in our own plaintext. While this may seem extraneous given
    we can already inject a payload, this particular attack lends itself to bypassing validation functions.
    Imagine if an application encrypts a URL-encoded payload with its application key and gives it to us as way of keeping state.
    The developer assumes we can't modify the ciphertext without corrupting the string, so they trust the ciphertext
    when it's received.

    CBC will XOR the bitshift of the edited cipher block
    with the next blocks. To exploit this structure, we must
    craft a payload in reverse such that it creates our desired string.
    To do this, we need a known plaintext and a desired plaintext.
    We fill the targeted block with the known plaintext.
    We XOR our desired text, 'hiya;admin=true;', with the plaintext to find the "difference".
    Finally, we XOR the difference with the original cipher block.

    comment1=cooking
    %20MCs;userdata=
    aaaaaaaaaaaaaaaa
    ;comment2=%20lik
    e%20a%20pound%20
    of%20baconPPPPPP

    
    Conditions:
        * CBC, CTR, or a stream cipher is being used
        * The user has access to an oracle that allows encryption of arbitrary plaintext and returns the ciphertext.
    """

    def __init__(self, oracle: EncryptionOracle, block_size: int=16):
        """
        Parameters:
            oracle (EncryptionOracle): An oracle that takes in arbitrary plaintext and returns the ciphertext.
            block_size          (int): Block size of the underlying block cipher.
        """
        self.oracle = oracle
        self.block_size = block_size


    def execute(self, desired_injection: bytes, index: int=16) -> Bytes:
        """
        Executes the attack.

        Parameters:
            desired_injection (bytes): Bytes to inject at `index`.
            index               (int): Index to inject the bytes.
        
        Return:
            Bytes: The manipulated ciphertext.
        """
        payload = b'a' * self.block_size
        ciphertext = self.oracle.encrypt(payload)

        end_of_block = index + self.block_size
        edited_cipher = Bytes(ciphertext)
        edited_cipher[index:end_of_block] = edited_cipher[index:end_of_block] ^ desired_injection ^ payload
        return edited_cipher
