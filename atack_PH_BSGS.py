import math
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


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


def bsgs(P, Q, m):
    step = int(math.sqrt(m)) + 1
    baby = {}
    cur = None
    for j in range(step):
        if cur is None:
            baby['O'] = j
        else:
            baby[cur] = j
        cur = point_addition(cur, P)

    factor = scalar_mul(P, step)
    factor_inv = point_inverse(factor)

    cur = Q
    for i in range(step):
        if cur is None:
            if 'O' in baby:
                j = baby['O']
                return i * step + j
        else:
            if cur in baby:
                j = baby[cur]
                return i * step + j
        cur = point_addition(cur, factor_inv)
    return None


def cto(congruences):
    x = 0
    M = 1
    for _, mod in congruences:
        M *= mod
    for con, mod in congruences:
        Mi = M // mod
        inv = pow(Mi, -1, mod)
        x += con * Mi * inv
    return x % M


# Параметры кривой
p = 310717010502520989590157367261876774703
a = 2
b = 3

g_x = 179210853392303317793440285562762725654
g_y = 105268671499942631758568591033409611165
G = (g_x, g_y)

b_x = 272640099140026426377756188075937988094
b_y = 51062462309521034358726608268084433317
B = (b_x, b_y)

q_x = 280810182131414898730378982766101210916
q_y = 291506490768054478159835604632710368904
Q = (q_x, q_y)

q = 155358505251260494795103074529582338902

factors = [
    (2, 1),
    (3, 7),
    (139, 1),
    (165229, 1),
    (31850531, 1),
    (270778799, 1),
    (179317983307, 1)
]

congruences = []
for p_i, e_i in factors:
    mod = p_i ** e_i
    cofactor = q // mod
    G_i = scalar_mul(G, cofactor)
    B_i = scalar_mul(B, cofactor)
    n_i = bsgs(G_i, B_i, mod)
    print(f"mod = {mod}, n_i = {n_i}")
    if n_i is not None:
        congruences.append((n_i, mod))

n = cto(congruences)
iv_hex = "07e2628b590095a5e332d397b8a59aa7"
ciphertext_hex = "8220b7c47b36777a737f5ef9caa2814cf20c1c1ef496ec21a9b4833da24a008d0870d3ac3a6ad80065c138a2ed6136af"

iv = bytes.fromhex(iv_hex)
ciphertext = bytes.fromhex(ciphertext_hex)

shared2 = scalar_mul(Q, n)[0]

sh = shared2
sha1 = hashlib.sha1()
sha1.update(str(sh).encode('ascii'))
key = sha1.digest()[:16]
cipher = AES.new(key, AES.MODE_CBC, iv)
try:
    flag = unpad(cipher.decrypt(ciphertext), 16)
    print(f"ФЛАГ НАЙДЕН! {flag.decode()}")
except ValueError as e:
    print(f"Не подходит: {e}")
