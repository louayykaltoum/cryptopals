
from pwn import *

s1 = "Burning 'em, if you ain't quick and nimble"
s2 = "I go crazy when I hear a cymbal"

key = 'ICE'

print(xor(s1, key).hex())
print(xor(s2, key).hex())
