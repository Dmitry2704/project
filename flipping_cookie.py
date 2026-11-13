#Задание:
@chal.route('/flipping_cookie/check_admin/<cookie>/<iv>/')
def check_admin(cookie, iv):
    cookie = bytes.fromhex(cookie)
    iv = bytes.fromhex(iv)

    try:
        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(cookie)
        unpadded = unpad(decrypted, 16)
    except ValueError as e:
        return {"error": str(e)}

    if b"admin=True" in unpadded.split(b";"):
        return {"flag": FLAG}
    else:
        return {"error": "Only admin can read the flag"}

@chal.route('/flipping_cookie/get_cookie/')
def get_cookie():
    expires_at = (datetime.today() + timedelta(days=1)).strftime("%s")
    cookie = f"admin=False;expiry={expires_at}".encode()

    iv = os.urandom(16)
    padded = pad(cookie, 16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(padded)
    ciphertext = iv.hex() + encrypted.hex()

    return {"cookie": ciphertext}
#решение:
import requests

BASE_URL = "https://aes.cryptohack.org/flipping_cookie&quot;

# Получаем зашифрованную куку
res = requests.get(f'{BASE_URL}/get_cookie/')
result = res.json()['cookie']
old_iv_hex = result[:32]
cookie_ct = result[32:]

old_iv = bytes.fromhex(old_iv_hex)

old_P = [ord('F'), ord('a'), ord('l'), ord('s'), ord('e')]

desired_P = [ord('T'), ord('r'), ord('u'), ord('e'), ord(';')]

positions = [6, 7, 8, 9, 10]

new_iv = bytearray(old_iv)
print(new_iv, 'Новый IV')
for pos, old, new in zip(positions, old_P, desired_P):
    new_iv[pos] = old_iv[pos] ^ old ^ new
    print(new_iv)

response = requests.get(f'{BASE_URL}/check_admin/{cookie_ct}/{new_iv.hex()}')
print(response.json()['flag'])
