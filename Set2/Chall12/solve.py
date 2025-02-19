from Crypto.Cipher import AES
from os import urandom
import base64
from Crypto.Util.Padding import pad


KEY = urandom(16)
text = base64.b64decode("""Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK""")


def encrypt_aes_ecb_with_payload(plaintext):
    cipher = AES.new(KEY, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext + text ,16))


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





def break_ecb(blocksize , len_unknow):
    guessed = b''
    for i in range(len_unknow):
        payload = b'a' *(blocksize - 1 - ( i % blocksize ))
        enc1 = encrypt_aes_ecb_with_payload(payload)[:len(payload) + len(guessed) + 1]
        for c in range(256):
            enc2 = encrypt_aes_ecb_with_payload(payload + guessed +chr(c).encode())[:len(payload) + len(guessed) + 1]
            if enc1 == enc2:
                guessed +=chr(c).encode()
                break
    return guessed.decode()




blocksize, to_guess = detect_blocksize()
mode = detect_mode(blocksize)
print(f'{blocksize = }')
print(f'{mode = }')
print(f'bytes to guess: {to_guess }')
print('Guessed text:\n')


if mode == "ECB":
    print(break_ecb(blocksize , to_guess))





