p = 28151
# Найти наименьший g,который является примитивным элементов Fp
q = list(primefac.primefac(p-1))
n = p-1
for i in range(2, p):
    flag = True
    for j in q:
        if pow(i, n//j, p) == 1:
            flag = False
            break
    if flag:
        print(i)
