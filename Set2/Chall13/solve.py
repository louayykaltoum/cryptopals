
import os 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = os.urandom(16)

def profile_for(email):
    email = email.replace('&', '').replace('=', '')
    return f'email={email}&uid=10&role=user'

def encrypt_profile(email, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(profile_for(email).encode()  , AES.block_size ))


def decrypt_profile(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext) , AES.block_size).decode()

def parse(encoded):
    return dict([pair.split('=') for pair in encoded.split('&')])

def check(ciphertext, key):
    return parse(decrypt_profile(ciphertext, key))

def challenge(email):
    print(check(encrypt_profile(email, key), key))
    
def extract_blocks(token, block_size=16):
    return [token[i:i+block_size] for i in range(0, len(token), block_size)]

def exploit():
    postfix = b'@gmail.com'
    email_prefix_length = 16 - len("email=") - len(postfix)
    to_enc = pad(b"admin", 16)
    email = b'A' * email_prefix_length + postfix + to_enc
    token = encrypt_profile(email.decode(), key)
    enc_blocks = extract_blocks(token)
    target_block = enc_blocks[1]
    print(target_block)
    email = b'A' * (16 + 3 - len("email=") - len(postfix)) + postfix
    token = encrypt_profile(email.decode(), key)
    enc_blocks = extract_blocks(token)
    crafted_token = enc_blocks[0] + enc_blocks[1] + target_block
    print(check(crafted_token, key))


exploit()