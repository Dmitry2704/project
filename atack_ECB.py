import requests
import json

URL = "https://aes.cryptohack.org/ecb_oracle/encrypt/&quot;

def encrypt(plaintext_hex):
    r = requests.get(f"{URL}{plaintext_hex}/")
    return r.json()["ciphertext"]

print("[*] Getting ciphertext samples...")

block1 = []
block2 = []

for i in range(16, 32):
    pad = "00" * i
    ciphertext = encrypt(pad)
    block1.append(ciphertext[32:64])
    block2.append(ciphertext[64:96])

samples = block1 + block2

print("[*] Starting attack...")

known = ""

for i in range(1, 33):
    if i <= 16:
        target = samples[-16 - i]
    else:
        target = samples[16 - i]

    for guess in range(32, 127):
        pad = "00" * (31 - len(known) // 2)
        payload = pad + known + format(guess, "02x")
        ciphertext = encrypt(payload)[32:64]

        if ciphertext == target:
            known += format(guess, "02x")
            print(f"Found: {chr(guess)} -> {bytes.fromhex(known).decode()}")

            if chr(guess) == "}":
                print(f"\n[+] FLAG: {bytes.fromhex(known).decode()}")
                exit()
            break
