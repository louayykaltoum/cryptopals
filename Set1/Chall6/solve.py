


def hamming_distance(s1,s2):
    return sum([bin(ord(a) ^ ord(b)).count('1') for a,b in zip(s1,s2)])  


s1 = "this is a test"
s2 = "wokka wokka!!!"

for i,b in zip(s1,s2):
    print(i,b)