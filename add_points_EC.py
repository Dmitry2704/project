def add_points(P, Q):
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
