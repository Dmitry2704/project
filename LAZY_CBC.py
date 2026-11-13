from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import requests
from binascii import unhexlify, hexlify

def decrypt(ciphertext_hex):
    url = f'http://aes.cryptohack.org/lazy_cbc/receive/{ciphertext_hex}'
    resp = requests.get(url).json()
    if 'error' in resp:
        error_msg = resp['error']
        hex_data = error_msg.split(': ')[1]
        return bytes.fromhex(hex_data)
    else:
        return None

X = b'\x00' * 16
X_hex = X.hex()

ciphertext = X_hex + X_hex

plaintext_bytes = decrypt(ciphertext)
if plaintext_bytes is None:
    print("Не удалось получить расшифрованный текст")
    exit()

P1 = plaintext_bytes[:16]
P2 = plaintext_bytes[16:]

KEY = bytes([a ^ b ^ c for a, b, c in zip(P1, P2, X)])
print("KEY =", KEY.hex())

url_flag = f'http://aes.cryptohack.org/lazy_cbc/get_flag/{KEY.hex()}'
flag_resp = requests.get(url_flag).json()['plaintext']
print(bytes.fromhex(flag_resp))

@chal.route('/ecb_oracle/encrypt/<plaintext>/')
def encrypt(plaintext):
    plaintext = bytes.fromhex(plaintext)

    padded = pad(plaintext + FLAG.encode(), 16)
    cipher = AES.new(KEY, AES.MODE_ECB)
    try:
        encrypted = cipher.encrypt(padded)
    except ValueError as e:
        return {"error": str(e)}

    return {"ciphertext": encrypted.hex()}
