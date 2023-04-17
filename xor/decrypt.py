import itertools

def xor_decrypt(data: bytes, key: bytes) -> bytes:
    decrypted = b''
    for i in range(len(data)):
        decrypted += bytes([data[i] ^ key[i % len(key)]])
    return decrypted

encrypted_flag = bytes.fromhex("5296a4c868a796802eb6d5d745bad6c145acd6c745b1d6ec69f185c668f19b")

# Brute-Force den 4-Byte-Schlüssel
for key in itertools.product(range(256), repeat=4):
    key_bytes = bytes(key)
    decrypted = xor_decrypt(encrypted_flag, key_bytes)
    if decrypted.startswith(b"HTB{"):
        print("Found key:", key_bytes)
        print("Decrypted flag:", decrypted.decode())
        break
