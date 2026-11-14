def tonelli_shanks(n, p):
    #Находит квадратный корень из n по модулю простого p

    #Проверка символа Лежандра(если результат != 1,то у числа нет квадратного корня по модулю p
    if pow(n, (p - 1) // 2, p) != 1:
        return None

    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    #Оптимизация(p =3 mod 4)
    if s == 1:
        root = pow(n, (p + 1) // 4, p)
        return (root, p - root)

    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1

    c = pow(z, q, p)
    R = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    M = s

    while t != 1:
        i = 1
        temp = pow(t, 2, p)
        while temp != 1:
            temp = pow(temp, 2, p)
            i += 1
            if i == M:
                return None

        b = pow(c, 2 ** (M - i - 1), p)
        M = i
        c = pow(b, 2, p)
        t = (t * c) % p
        R = (R * b) % p

    return (R, p - R)
