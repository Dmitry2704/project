import hashlib, socket, json
from Crypto.Util.number import bytes_to_long
import ecdsa
from random import randrange

n_order = ecdsa.ecdsa.generator_192.order()
G = ecdsa.ecdsa.generator_192

def sha1_int(msg):
    return bytes_to_long(hashlib.sha1(msg.encode()).digest())

def recv_line(f):
    data = b""
    while not data.endswith(b"\n"):
        chunk = f.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

def sign(z, d):
    while True:
        k = randrange(1, n_order)
        R = k * G
        r = R.x() % n_order
        if r == 0:
            continue
        s = (pow(k, -1, n_order) * (z + r * d)) % n_order
        return r, s

HOST, PORT = 'socket.cryptohack.org', 13381

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as f:
    f.connect((HOST, PORT))
    print(recv_line(f).decode())

    sigs = []
    seen_r = {}
    collision = None

    # запрашиваем sign_time, пока не поймаем повтор r 
    while collision is None:
        f.send(json.dumps({'option': 'sign_time'}).encode() + b'\n')
        resp = json.loads(recv_line(f))
        r_hex = resp['r']
        if r_hex in seen_r:
            collision = (seen_r[r_hex], resp)
        else:
            seen_r[r_hex] = resp

    sig1, sig2 = collision
    print("Найдена коллизия r:", sig1, sig2)

    r  = int(sig1['r'], 16)
    s1 = int(sig1['s'], 16)
    s2 = int(sig2['s'], 16)
    z1 = sha1_int(sig1['msg'])
    z2 = sha1_int(sig2['msg'])

    k = ((z1 - z2) * pow((s1 - s2) % n_order, -1, n_order)) % n_order
    d = ((s1 * k - z1) * pow(r, -1, n_order)) % n_order

    Q = d * G
    print("Проверка своего ключа: совпадает ли восстановленный k с реальным по r?",
          (k * G).x() % n_order == r)

    z = sha1_int('unlock')
    r_new, s_new = sign(z, d)

    f.send(json.dumps({
        'option': 'verify',
        'msg': 'unlock',
        'r': hex(r_new)[2:],
        's': hex(s_new)[2:]
    }).encode() + b'\n')

    print(recv_line(f).decode())
