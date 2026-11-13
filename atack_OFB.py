#Задание
from Crypto.Cipher import AES
import os

@chal.route('/symmetry/encrypt/<plaintext>/<iv>/')
def encrypt(plaintext, iv):
    plaintext = bytes.fromhex(plaintext)
    iv = bytes.fromhex(iv)
    if len(iv) != 16:
        return {"error": "IV length must be 16"}

    cipher = AES.new(KEY, AES.MODE_OFB, iv)
    encrypted = cipher.encrypt(plaintext)
    ciphertext = encrypted.hex()

    return {"ciphertext": ciphertext}

@chal.route('/symmetry/encrypt_flag/')
def encrypt_flag():
    iv = os.urandom(16)

    cipher = AES.new(KEY, AES.MODE_OFB, iv)
    encrypted = cipher.encrypt(FLAG.encode())
    ciphertext = iv.hex() + encrypted.hex()

    return {"ciphertext": ciphertext}
#решение
import requests
res = requests.get('https://aes.cryptohack.org/symmetry/encrypt_flag/')
s = res.json()['ciphertext']

IV = s[:32]
plain = s[32:]

def encrypt(text, iv):
    response = requests.get(f'https://aes.cryptohack.org/symmetry/encrypt/{text}/{iv}')

    return bytes.fromhex(response.json()['ciphertext'])

print(encrypt(plain, IV))
