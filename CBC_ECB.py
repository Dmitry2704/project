#задание
from Crypto.Cipher import AES
import os


@chal.route('/ecbcbcwtf/decrypt/<ciphertext>/')
def decrypt(ciphertext):
    ciphertext = bytes.fromhex(ciphertext)

    cipher = AES.new(KEY, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
    except ValueError as e:
        return {"error": str(e)}

    return {"plaintext": decrypted.hex()}

@chal.route('/ecbcbcwtf/encrypt_flag/')
def encrypt_flag():
    iv = os.urandom(16)

    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(FLAG.encode())
    ciphertext = iv.hex() + encrypted.hex()

    return {"ciphertext": ciphertext}
#решение
import requests
from pwn import xor
s = '0e113a84c244be3e9e946557caaf4da8b692494e70b23b896db3784f66ed2c1a471e17166062d17787e3624605fb5adf'
IV = bytes.fromhex(s[0:32])
C1 = bytes.fromhex(s[32:64])
C2 = bytes.fromhex(s[64:96])
def encrrypt(text):
    response = requests.get(f'http://aes.cryptohack.org/ecbcbcwtf/decrypt/{text}')
    return bytes.fromhex(response.json()['plaintext'])

d1 = encrrypt(C1.hex())
d2 = encrrypt(C2.hex())
P1 = (xor(d1,  IV))
P2 = (xor(d2,  C1))
print((P1+P2).decode())
