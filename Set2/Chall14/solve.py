from Crypto.Cipher import AES
from os import urandom
import base64
from Crypto.Util.Padding import pad


KEY = urandom(16)
text = base64.b64decode("""Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK""")

secret = urandom(16)

def encrypt_aes_ecb_with_payload(plaintext):
    cipher = AES.new(KEY, AES.MODE_ECB)
    return cipher.encrypt(pad( secret +  plaintext + text ,16))


def detect_blocksize():
    temp = b"a"
    enc1 = encrypt_aes_ecb_with_payload(temp)
    for i in range(1, 100):
        enc2 = encrypt_aes_ecb_with_payload(temp*i)
        if (len(enc1) != len(enc2)):
            return (len(enc2) - len(enc1)) , len(enc2) - 16 - (i)

        
def detect_mode(blocksize):
    enc = encrypt_aes_ecb_with_payload(b"a"*2*blocksize)
    if enc[0:blocksize] == enc[blocksize:2*blocksize]:
        return "ECB"
    else:
        return "CBC"

def extract_blocks(token, block_size=16):
    return [token[i:i+block_size] for i in range(0, len(token), block_size)]

def detect_prefix(blocksize):
    enc = extract_blocks(encrypt_aes_ecb_with_payload(b'a'*blocksize*2))
    a = ([int(enc[i] == enc[i+1]) for i in range(len(enc) - 1)])
    for i in range(blocksize):
        enc = extract_blocks(encrypt_aes_ecb_with_payload(b'a'*blocksize*2 + b'a'*i))
        b = ([int(enc[i] == enc[i+1]) for i in range(len(enc) - 1)])
        if sum(a) != sum(b):
            return  (blocksize - i) + blocksize * (b.index(1) -1 )
    else :
        return blocksize * a.index(1)


        



def break_ecb(blocksize , len_unknow , prefix = 0):
    guessed = b''
    for i in range(len_unknow):
        payload = b'a' * (blocksize - 1 - ( i % blocksize ))
        enc1 = encrypt_aes_ecb_with_payload(b'a' * ( (prefix % 16 + 1) * 16 - prefix) + payload)[((prefix % 16) +1) * 16 : ][:len(payload) + len(guessed) + 1]
        for c in range(256):
            enc2 = encrypt_aes_ecb_with_payload( b'a' * ( (prefix % 16 + 1) * 16 - prefix) + payload + guessed +chr(c).encode())[((prefix % 16) +1) * 16 : ][:len(payload) + len(guessed) + 1]
            if enc1 == enc2:
                guessed +=chr(c).encode()
                break
    return guessed.decode()






blocksize, to_guess = detect_blocksize()
mode = detect_mode(blocksize)
print(f'{blocksize = }')
print(f'{mode = }')
print(f'bytes to guess: {to_guess}')
print('Guessed text:\n')

def detect_prefix(blocksize):
    enc = extract_blocks(encrypt_aes_ecb_with_payload(b'a'*blocksize*2))
    a = ([int(enc[i] == enc[i+1]) for i in range(len(enc) - 1)])
    for i in range(blocksize):
        enc = extract_blocks(encrypt_aes_ecb_with_payload(b'a'*blocksize*2 + b'a'*i))
        b = ([int(enc[i] == enc[i+1]) for i in range(len(enc) - 1)])
        if sum(a) != sum(b):
            return  (blocksize - i) + blocksize * (b.index(1) -1 )
    else :
        return blocksize * a.index(1)



print(break_ecb(blocksize , to_guess , detect_prefix(16)))