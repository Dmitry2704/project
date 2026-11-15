'''WOTS ATTACK #2 — переиспользование ключа на множестве сообщений
(независимая генерация приватного ключа, но key reuse на 20 подписях)

ОТЛИЧИЕ ОТ ЗАДАЧИ 1
priv_key[i] = hash(urandom(KEY_LEN)) — каждая из 32 цепочек НЕЗАВИСИМА
(общего seed нет, второго бага из первой задачи тут нет).
Значит донора для позиции i нельзя брать с другого индекса j≠i —
чужая цепочка никогда не сойдётся с нужным pub_key[i].

НО: один и тот же ключ w использован для подписи 20 разных сообщений
(+ ещё одного, message2, которое мы должны подделать).
Это и есть используемая уязвимость — classic WOTS key reuse,
только теперь у нас много попыток вместо одной.

ЧТО ИЗВЕСТНО / ЧТО НЕТ
Известно:  public_key, iv, enc, 20 пар (message_k, signature_k)
Неизвестно: signature2 — подпись для message2, её нет в файле физически.

ВОССТАНОВЛЕНИЕ message2
message2 не хранится в файле, но легко составляется вручную,
т.к. известна формула генерации из кода задачи:
message2 = f"{public_key[0]} sent 999999 WOTScoins to me"
(pub_key[0] — известная часть, остальное захардкожено в условии).
h2 = список байт sha256(message2)

УСЛОВИЕ ПОДДЕЛКИ ЭЛЕМЕНТА sig2[i]
Для позиции i ищем любое сообщение k (из 20), для которого:
h_k[i] >= h2[i]
Тогда: sig2[i] = hash^(h_k[i]-h2[i]) (sig_k[i])
(дохэшировать можно только вперёд — от меньшей "глубины" к большей,
как и в задаче 1, но здесь без общего K через seed — просто сырое
сравнение байт хэша сообщений на одной и той же позиции i).

ПОЧЕМУ ПОЧТИ ВСЕГДА ЗАКРЫВАЮТСЯ ВСЕ 32 ПОЗИЦИИ
Вероятность неудачи для одного кандидата ≈ 1/2.
Вероятность, что все 20 кандидатов не подойдут для одной позиции:
(1/2)^20 ≈ 1 на миллион.
Для 32 независимых позиций суммарный риск (что хоть одна не найдёт
донора) ≈ 32 × (1/2)^20 ≈ 1 к 33000 — всё ещё очень мала.

ПРАКТИЧЕСКИЙ АЛГОРИТМ
1. Восстановить message2 руками (по формуле из кода + pub_key[0]).
2. Посчитать h2 = sha256(message2) -> список байт.
3. Для каждой позиции i (0..31):
     для каждого сообщения k (из 20):
       если h_k[i] >= h2[i]:
         raz = h_k[i] - h2[i]
         sig2[i] = дохэшировать sig_k[i] ещё raz раз
         break (нашли донора для этой позиции, переходим к i+1)
4. Проверить valid(h2, sig2) через дохэш до pub_key.
5. aes_key = bytes([s[0] for s in sig2]); AES-CBC(iv, enc) -> flag.

ГЛАВНОЕ ОТЛИЧИЕ ОТ ЗАДАЧИ 1 (структура перебора)
Задача 1: внешний цикл по позициям i, внутренний — по 32 позициям j
          ОДНОЙ подписи (донор — другой индекс той же цепочки,
          возможно благодаря общему seed).
Задача 2: внешний цикл по позициям i, внутренний — по 20 РАЗНЫМ
          сообщениям k (донор — та же позиция i, но из другой подписи,
          возможно благодаря простому key reuse без общего seed).

ОБЩАЯ ИДЕЯ ОБЕИХ ЗАДАЧ
Если у атакующего есть много "точек" одной или нескольких хэш-цепочек
(через связанный ключ или через много переиспользований одного ключа),
почти всегда можно набрать полный комплект точек, чтобы дойти
(дохэшировать вперёд) до любой нужной новой подписи.'''
import json
from hashlib import sha256
from Crypto.Cipher import AES
with open('data.json') as f:
    wots = json.loads(f.read())
    sig = wots['signatures']
    public_key = wots['public_key']
    iv = wots['iv']
    enc = wots['enc']
    pb_0 = public_key[0]
    msg2 = f"{pb_0} sent 999999 WOTScoins to me"
    hash_m2_ord = list(sha256(msg2.encode()).digest())


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


    def per(msg):
        hash_m_ord = list(sha256(msg.encode()).digest())
        return hash_m_ord
    sig2 = []
    for i in range(len(hash_m2_ord)):
        for j in sig:
            hash_k_ord = per(j['message'])
            if hash_k_ord[i] >= hash_m2_ord[i]:
                raz = hash_k_ord[i] - hash_m2_ord[i]
                sh = bytes.fromhex(j['signature'][i])
                for _ in range(raz):
                    sh = sha256(sh).digest()
                sig2.append(sh)
                break
    v = (valid(hash_m2_ord, sig2))
    if v == 'VALID':
        aes_key = bytes([s[0] for s in sig2])
        cipher = AES.new(aes_key, AES.MODE_CBC, bytes.fromhex(iv))
        encrypted = cipher.decrypt(bytes.fromhex(enc))
        print(encrypted)
