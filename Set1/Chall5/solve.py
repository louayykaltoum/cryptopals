
from pwn import *

s1 = """Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"""

key = 'ICE'

def xor_with_repeating_key(s,key):
    output = ''
    for i in range(len(s)):
        output += chr(ord(s[i]) ^ ord(key[i % len(key)]))
    return output

print(xor_with_repeating_key(s1,key).encode().hex())
