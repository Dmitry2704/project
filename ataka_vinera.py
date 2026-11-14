#Решение работает только для d < (N/3)^0.25
from math import isqrt

def continued_fraction(n, d):
    "Генерирует цепную дробь для n/d"
    while d != 0:
        q = n // d
        yield q
        n, d = d, n - q * d


def convergents(frac_gen):
    h_prev, h_curr = 0, 1
    k_prev, k_curr = 1, 0

    for q in frac_gen:
        h_new = q * h_curr + h_prev
        k_new = q * k_curr + k_prev
        yield h_new, k_new
        h_prev, h_curr = h_curr, h_new
        k_prev, k_curr = k_curr, k_new


def is_square(n):
    if n < 0:
        return False
    s = isqrt(n)
    return s * s == n


def wiener_attack(N, e):
    for k, d in convergents(continued_fraction(e, N)):
        # k должно быть положительным
        if k == 0:
            continue

        # Проверка делимости
        if (e * d - 1) % k != 0:
            continue

        # Вычисляем φ(N)
        phi = (e * d - 1) // k

        # Решаем квадратное уравнение
        b = N - phi + 1  # p + q
        D = b * b - 4 * N  # дискриминант

        if not is_square(D):
            continue

        sqrt_D = isqrt(D)
        p = (b - sqrt_D) // 2
        q = (b + sqrt_D) // 2

        # Проверяем, что нашли правильные p и q
        if p * q == N:
            return d

    return None
