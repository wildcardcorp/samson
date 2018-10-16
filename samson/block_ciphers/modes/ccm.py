from samson.macs.cbc_mac import CBCMAC
from samson.block_ciphers.modes.ctr import CTR
from samson.utilities.bytes import Bytes


class CCM(object):
    def __init__(self, key, cipher, mac_len):
        self.key = key
        self.cipher = cipher
        self.cmac = CBCMAC(self.key, self.cipher)
        self.mac_len = mac_len

        self.enc_obj = self.cipher(key)
        self.ctr = CTR(self.enc_obj.encrypt, b'\x00' * 16, 16)

    
    def __repr__(self):
        return f"<CCM: enc_obj={self.enc_obj}, key={self.key}, ctr={self.ctr}>"


    def __str__(self):
        return self.__repr__()
    

    # https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38c.pdf
    def encrypt(self, nonce, plaintext, data):
        data_len = len(data)

        q = 15 - len(nonce)
        flags = (64 * (data_len > 0)) + 8 * (((self.mac_len) - 2) // 2) + (q - 1)
        b_0 = Bytes(flags) + nonce + int.to_bytes(len(plaintext), q, 'big')

        formatted_nonce = Bytes(q - 1) + nonce

        data_len_encoded = b''
        if data_len > 0:
            if data_len < ((2 ** 16) - (2 ** 8)):
                size = 2
            elif data_len < (2 ** 32):
                data_len_encoded = b'\xFF\xFE'
                size = 4
            else:
                data_len_encoded = b'\xFF\xFF'
                size = 8
            
            data_len_encoded += int.to_bytes(data_len, size, 'big')
        
        padded_data = data_len_encoded + data + (b'\x00' * (16 - (len(data_len_encoded + data) % 16)))
        padded_plaintext = plaintext + (b'\x00' * (16 - (len(plaintext) % 16)))

        self.ctr.nonce = formatted_nonce
        keystream = self.ctr.encrypt(Bytes(b'').zfill(len(plaintext) + 16))

        T = self.cmac.generate(b_0 + padded_data + padded_plaintext, pad=False)

        return (keystream[len(T):] ^ (plaintext)) + (T ^ keystream[:len(T)])[:self.mac_len]


    def decrypt(self, nonce, ciphertext, data):
        pass