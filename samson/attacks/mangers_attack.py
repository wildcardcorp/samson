from samson.utilities.bytes import Bytes
from samson.oracles.padding_oracle import PaddingOracle
from samson.public_key.rsa import RSA
import math

import logging
log = logging.getLogger(__name__)


# AKA OAEP padding oracle
# http://archiv.infsec.ethz.ch/education/fs08/secsem/Manger01.pdf
class MangersAttack(object):
    """
    Performs a plaintext recovery attack.
    
    Manger's attack stems from a padding oracle on RSA-OAEP. According to OAEP's specification, the first byte
    *has* to be zero. If the code checks this and leaks whether it's zero or not, we can efficiently retrieve
    the plaintext through an adaptive chosen-plaintext attack.
    """

    def __init__(self, padding_oracle: PaddingOracle, rsa: RSA):
        """
        Parameters:
            padding_oracle (PaddingOracle): An oracle that takes in bytes and returns whether the first byte of the decrypted plaintext is zero.
            rsa                      (RSA): An RSA instance containing the public key parameters.
        """
        self.oracle = padding_oracle
        self.rsa = rsa


    def _greater_equal_B(self, f, c, e, N):
        f_e = pow(f, e, N)
        return self.oracle.check_padding(Bytes((c * f_e) % N))


    def execute(self, ciphertext: bytes) -> Bytes:
        """
        Executes Manger's attack.

        Parameters:
            ciphertext (bytes): The ciphertext to decrypt.
        
        Returns:
            Bytes: The ciphertext's corresponding plaintext.
        """
        ciphertext = Bytes.wrap(ciphertext)
        ct_int = ciphertext.int()

        k = math.ceil(math.log(self.rsa.n, 256))
        B = 2 ** (8 * (k - 1))
        n = self.rsa.n
        e = self.rsa.e

        log.debug(f"k: {k}, B: {B}, n: {n}, e: {e}")

        # Step 1
        f1 = 2
        log.info("Starting step 1")

        while not self._greater_equal_B(f1, ct_int, e, n):
            f1 *= 2

        f1 //= 2
        log.debug(f"Found f1: {f1}")


        # Step 2
        nB = n + B
        nB_B = nB // B
        f2 = nB_B * f1

        log.info("Starting step 2")
        while self._greater_equal_B(f2, ct_int, e, n):
            f2 += f1


        log.debug(f"Found f2: {f2}")

        # Step 3
        div_mod = 1 if n % f2 else 0
        m_min = n // f2 + div_mod
        m_max = nB // f2
        BB = 2*B
        diff = m_max - m_min
        ctr = 0

        log.info("Starting step 3")
        log.debug(f"B-(diff * f2) = {B - (diff * f2)}")
        while diff > 0:
            if ctr % 100 == 0:
                log.debug(f"Iteration {ctr} difference: {diff}")

            f = BB // diff
            f_min = f * m_min
            i = f_min // n
            iN = i*n

            div_mod = 1 if iN % m_min else 0
            f3 = iN // m_min + div_mod
            iNB = iN + B

            if self._greater_equal_B(f3, ct_int, e, n):
                div_mod = 1 if iNB % f3 else 0
                m_min = iNB // f3 + div_mod
            else:
                m_max = iNB // f3

            diff = m_max - m_min
            ctr += 1


        return Bytes(m_min)
