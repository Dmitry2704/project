'''УЯЗВИМОСТЬ 1: переиспользование ключа (key reuse)
Один и тот же приватный ключ подписал 2 разных сообщения.
Это база любой атаки на WOTS — one-time подписи нельзя переиспользовать.

УЯЗВИМОСТЬ 2: зависимая генерация приватного ключа
priv_seed = urandom(KEY_LEN)
for _ in range(KEY_LEN):
    priv_seed = hash(priv_seed)
    priv_key.append(priv_seed)

Вместо 32 независимых секретов — все 32 элемента являются
последовательными хэшами ОДНОГО seed S:
priv_key[i] = hash^(i+1)(S)

ФОРМУЛА КООРДИНАТЫ (СТЕПЕНИ) ЭЛЕМЕНТА ПОДПИСИ

sig[i] = hash^(255-h[i])(priv_key[i])
priv_key[i] = hash^(i+1)(S)

=> любой элемент подписи — точка на ЕДИНОЙ цепочке от S:
K(i) = (i+1) + (255 - h[i])

где h[i] — i-й байт хэша сообщения.

СУТЬ АТАКИ

Все элементы (и sig1, и sig2, с любыми индексами) лежат на одной
прямой (цепочке от S). Значит можно взять любой известный элемент
sig1[j] (координата K1[j]) и дойти до нужного sig2[i]
(координата K2[i]), если донор лежит не дальше цели:

K1[j] <= K2[i]  =>  sig2[i] = hash^(K2[i]-K1[j]) (sig1[j])

Хэш необратим -> двигаться можно только вперёд по цепочке
(от меньшей координаты к большей).

ПОЧЕМУ ПОЧТИ ВСЕГДА ЗАКРЫВАЮТСЯ ВСЕ 32 БАЙТА

Для каждого i перебираем всех 32 кандидатов j (а не только j=i,
как в обычной наивной key-reuse атаке). Вероятность, что НИ ОДИН
из 32 не подойдёт ≈ (1/2)^32 -> практически 0.
Поэтому подделывается ВСЯ подпись целиком, а не только ~половина
байт (как было бы при обычном key reuse с независимыми цепочками).

ПРАКТИЧЕСКИЙ АЛГОРИТМ

1. Посчитать K1[j] для всех j (по sig1 и хэшу message1).
2. Посчитать K2[i] для всех i (по хэшу message2).
3. Для каждого i найти любой j с K1[j] <= K2[i], дохэшировать
   sig1[j] на (K2[i]-K1[j]) шагов -> получить sig2[i].
4. Проверить валидность через дохэш до pub_key.
5. Использовать подделанную sig2 (например, как AES-ключ)
   дальше по сценарию'''

import json
from hashlib import sha256
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
KEY_LEN = 32
BYTE_MAX = 255
def valid(hash, sig):
    for i in range(len(hash)):
        sh = sig[i]
        for j in range(hash[i] + 1):
            sh = sha256(sh).digest()
        if public_key[i] == sh.hex():
            continue
        else:
            return 'NO VALID'
    return 'VALID'
with open('wots1.json') as f:
    wots = json.loads(f.read())
    public_key = wots['public_key']
    msg = wots['message']
    sig1 = wots['signature']
    sig1_bytes = [bytes.fromhex(s) for s in sig1]
    iv = wots['iv']
    enc = wots['enc']
    hash_m = sha256(msg.encode()).digest()
    hash_m_ord = list(hash_m)
    s1 = valid(hash_m_ord, sig1_bytes)
    hash_m_2 = sha256(b"Sign for flag").digest()
    hash_m_2_ord = list(hash_m_2)
    K1 = [(j + 1) + (BYTE_MAX - hash_m_ord[j]) for j in range(KEY_LEN)]
    K2 = [(i + 1) + (BYTE_MAX - hash_m_2_ord[i]) for i in range(KEY_LEN)]
    sig2 = []
    for i in range(len(K1)):
        for j in range(len(K2)):
            if K1[j] <= K2[i]:
                raz = K2[i] - K1[j]
                sh = bytes.fromhex(sig1[j])
                for _ in range(raz):
                    sh = sha256(sh).digest()
                sig2.append(sh)
                break
    print(K1)
    print(K2)
    s2 = valid(hash_m_2_ord, sig2)
    if s2 == 'VALID' and s1 == 'VALID':
        aes_key = bytes([s[0] for s in sig2])
        plain = AES.new(aes_key, AES.MODE_CBC, bytes.fromhex(iv))
        decrypted = plain.decrypt(bytes.fromhex(enc))
        print(decrypted.decode())
