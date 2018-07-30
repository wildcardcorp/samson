from Crypto.Cipher import AES
from samson.utilities import *

def encrypt_aes_cbc(key, iv, message, pad=True):
    encryptor = AES.new(key, AES.MODE_ECB)
    if pad:
        padded_msg = pkcs7_pad(message)
    else:
        padded_msg = message
        
    ciphertext = b''

    last_block = iv
    for block in get_blocks(padded_msg):
        enc_block = encryptor.encrypt(bytes(xor_buffs(last_block, block)))
        ciphertext += enc_block
        last_block = enc_block

    return ciphertext


def decrypt_aes_cbc(key, iv, message, unpad=True):
    encryptor = AES.new(key, AES.MODE_ECB)
    plaintext = b''

    last_block = iv
    for block in get_blocks(message):
        enc_block = xor_buffs(last_block, encryptor.decrypt(block))
        plaintext += enc_block
        last_block = block

    if unpad: plaintext = pkcs7_unpad(plaintext)
    return plaintext
