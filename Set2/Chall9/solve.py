

text = "YELLOW SUBMARINE"

def padding(text, block_size):
    pad = block_size - len(text) % block_size
    return text + chr(pad) * pad

print(padding(text, 20).encode())