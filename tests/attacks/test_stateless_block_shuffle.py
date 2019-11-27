#!/usr/bin/python3
from samson.block_ciphers.rijndael import Rijndael
from samson.block_ciphers.modes.ecb import ECB

from samson.utilities.general import rand_bytes
from samson.utilities.manipulation import get_blocks
from samson.padding.pkcs7 import PKCS7

key_size = 16
block_size = 16
key = rand_bytes(key_size)

aes = Rijndael(key)
ecb = ECB(aes)

def parse_user(user):
    # Prevent dictionary randomization
    keys = ['email', 'uid', 'role']
    return '&'.join(['{}={}'.format(k, user[k].replace("=", "").replace("&", "")) for k in keys])



def profile_for(email):
    user = {'email' : email, 'uid' : '10', 'role': 'user'}
    return ecb.encrypt(parse_user(user).encode())


def login(cipherbytes):
    plaintext = ecb.decrypt(cipherbytes)
    user = {k: v for k,v in [(*keyval.split("="),) for keyval in plaintext.decode().split('&')]}
    print(user)
    return user['role'] == 'admin'


pkcs7 = PKCS7(block_size)

if __name__ == '__main__':
    user = profile_for('foobar@email.com')
    assert login(user) == False

    # We exploit ECB's stateless block structure and rearrange the blocks.
    # email=foo@email.
    # admin\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B
    # com&uid=10&role=
    # user

    # block_size = 16
    # email_block_left = block_size - len('email=')
    # injection = 'admin'
    # injected_cipher = get_blocks(profile_for('foo@email.' + pkcs7_pad(injection.encode()).decode() + 'com'))
    # print('Is Admin? {}'.format(login(bytes(injected_cipher[0] + injected_cipher[2] + injected_cipher[1]))))

    # Inputs
    input_mask = b'email={}&uid=10&role=(!)'
    injections = [b'admin']
    block_size = 16
    encryptor = profile_for


    # Find differiental
    diff_location = input_mask.decode().format('').index('(!)')
    diff_block_num = diff_location // 16
    diff_prefix_len = diff_location % 16


    # Find our injection point
    mask_location = input_mask.decode().format('<MASK>').index('<MASK>')
    exploit_block_num = mask_location // block_size + 1
    exploit_padding_len = block_size - diff_prefix_len


    # Pad injection to next block boundary
    exploit = b'a' * exploit_padding_len
    diff_block_num += 1


    # Build exploit block
    injection_location = block_size - mask_location

    exploit = exploit[:injection_location] + pkcs7.pad(injections[0]) + exploit[injection_location:]
    diff_block_num += 1


    # Send exploit block to server
    exploit_ciphertext = encryptor(exploit.decode())


    # Rearrange blocks to complete valid payload
    blocks = get_blocks(exploit_ciphertext, block_size)

    blocks[diff_block_num] = blocks[exploit_block_num]
    del blocks[exploit_block_num]

    crafted_payload = b''.join(blocks)
    print(login(crafted_payload))
