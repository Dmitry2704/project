#задание
FLAG = "crypto{???????????????}"


def bxor(a, b):
 return bytes(x ^ y for x, y in zip(a, b))


def hash(data):
 data = pad(data, 16)
 out = b"\x00" * 16
 for i in range(0, len(data), 16):
 blk = data[i:i+16]
 out = bxor(AES.new(blk, AES.MODE_ECB).encrypt(out), out)
 return out


class Challenge():
 def __init__(self):
 self.before_input = "You'll never forge my signatures!\n"
 self.key = os.urandom(16)

 def challenge(self, msg):
 if "option" not in msg:
 return {"error": "You must send an option to this server."}

 elif msg["option"] == "sign":
 data = bytes.fromhex(msg["message"])
 if b"admin=True" in data:
 return {"error": "Unauthorized to sign message"}
 sig = hash(self.key + data)

 return {"signature": sig.hex()}

 elif msg["option"] == "get_flag":
 sent_sig = bytes.fromhex(msg["signature"])
 data = bytes.fromhex(msg["message"])
 real_sig = hash(self.key + data)

 if real_sig != sent_sig:
 return {"error": "Invalid signature"}

 if b"admin=True" in data:
 return {"flag": FLAG}
 else:
 return {"error": "Unauthorized to get flag"}

 else:
 return {"error": "Invalid option"}

#решение
#Скрипт расширение длины

import socket
import json
from Crypto.Cipher import AES

def bxor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def next_state(block, current_state):
    cipher = AES.new(block, AES.MODE_ECB)
    encrypted = cipher.encrypt(current_state)
    return bxor(encrypted, current_state)

HOST = 'socket.cryptohack.org'
PORT = 13388

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))
print(sock.recv(1024).decode())

# Подписываем msg1
msg1 = b"a" * 15
sign_request = {"option": "sign", "message": msg1.hex()}
sock.send(json.dumps(sign_request).encode() + b'\n')
response = json.loads(sock.recv(1024).decode())
sig1 = bytes.fromhex(response["signature"])
print(f"sig1 = {sig1.hex()}")

# Вычисляем sig2
block2 = b"a" * 15 + b"\x01"              # 16 байт
block3 = b"admin=Trueaaaaaa"               # 16 байт
block4 = b"\x10" * 16                      # паддинг (16 байт)

out3 = next_state(block3, sig1)
sig2 = next_state(block4, out3)
print(f"sig2 = {sig2.hex()}")

# Отправляем msg2
msg2 = block2 + block3  # 32 байта
flag_request = {
    "option": "get_flag",
    "message": msg2.hex(),
    "signature": sig2.hex()
}

sock.send(json.dumps(flag_request).encode() + b'\n')
response = json.loads(sock.recv(1024).decode())
print(response)
sock.close()
