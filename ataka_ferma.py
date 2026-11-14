#Атака Ферма при условии что p приблизительно равно q(a-b = p, a+b = q)
#Задание
def getPrimes(bitsize):
    r = random.getrandbits(bitsize)
    p, q = r, r
    while not isPrime(p):
        p += random.getrandbits(bitsize//4)
    while not isPrime(q):
        q += random.getrandbits(bitsize//8)
    return p, q
#Решение
def ferma(n):
    a = math.isqrt(n)
    if a**2 == n:
        return a

    a += 1
    while True:
        b2 = a**2 - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1
