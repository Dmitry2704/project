import socket
import json
p = 2**256 - 2**224 + 2**192 + 2**96 - 1
a = -3 % p
n = 115792089210356248762697446949407573529996955224135760342422259061068512044369
d_inv = pow(2, -1, n)
Q = (int('0x3B827FF5E8EA151E6E51F8D0ABF08D90F571914A595891F9998A5BD49DFA3531', 16), int('0xAB61705C502CA0F7AA127DEC096B2BBDC9BD3B4281808B3740C320810888592A', 16))
def point_addition(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P

    x1, y1 = P
    x2, y2 = Q

    if x1 == x2 and (y1 + y2) % p == 0:
        return None

    if P != Q:
        lam = ((y2 - y1) * pow((x2 - x1) % p, -1, p)) % p
    else:
        lam = ((3 * x1 * x1 + a) * pow((2 * y1) % p, -1, p)) % p

    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p

    return (x3, y3)


def point_inverse(P: tuple):
    if P is None:
        return None
    return (P[0], -P[1] % p)


def scalar_mul(P, n):
    Q = P
    R = None
    while n > 0:
        if n & 1:
            R = point_addition(R, Q)
        Q = point_addition(Q, Q)
        n = n // 2
    return R
g_x, g_y = scalar_mul(Q, d_inv)
HOST = 'socket.cryptohack.org'
PORT = 13382

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    data = s.recv(4096)
    print(data.decode())
    trust = {'private_key': 2, 'host': "www.bing.com", 'curve': 'secp256r1', 'generator': [int(g_x), int(g_y)]}
    s.send(json.dumps(trust).encode()+ b'\n')
    data = s.recv(4096)
    print(data.decode())
