from pwn import xor
import string

s1 = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

def scoring(s):
    return sum([1 for i in s if i.upper() in string.ascii_uppercase])

def xor(s1 , c):
    return ''.join([chr(i ^ c ) for i in s1])

temp = [xor(bytes.fromhex(s1), i) for i in range(256)]

print(max(temp, key = scoring))