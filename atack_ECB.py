import requests

URL = "https://aes.cryptohack.org/ecb_oracle/encrypt/"

def encrypt(data: bytes) -> str:
    return requests.get(f"{URL}{data.hex()}/").json()["ciphertext"]

known = b""

while not known.endswith(b"}"):
    n = len(known)

    pad_len = 15 - (n % 16)
    block_no = n // 16
    ct = encrypt(b"\x00" * pad_len)
    target = ct[block_no * 32 : block_no * 32 + 32]

    prefix = (b"\x00" * 15 + known)[-15:]
    for guess in range(32, 127):
        probe = encrypt(prefix + bytes([guess]))[:32]
        if probe == target:
            known += bytes([guess])
            print(known.decode())
            break

print("FLAG:", known.decode())
