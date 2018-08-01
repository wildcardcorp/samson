from samson.utilities import pkcs7_pad, pkcs7_unpad
from Crypto.Cipher import AES

def encrypt_aes_ecb(key, message):
    return AES.new(key, AES.MODE_ECB).encrypt(pkcs7_pad(message))

def decrypt_aes_ecb(key, message):
    return pkcs7_unpad(AES.new(key, AES.MODE_ECB).decrypt(message))