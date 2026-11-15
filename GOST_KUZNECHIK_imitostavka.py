R_S = shifr(bytes(16))
K1_s = shift(R_S)
K2_s = shift(K1_s)

P = '1122334455667700ffeeddccbbaa9988' \
    '00112233445566778899aabbcceeff0a' \
    '112233445566778899aabbcceeff0a00' \
    '2233445566778899aabbcceeff0a0011'

def imitostavka(pt):
    if isinstance(pt, str):
        pt = bytes.fromhex(pt)
    if not pt:
        raise ValueError("пустое сообщение")

    blocks = [pt[i:i+16] for i in range(0, len(pt), 16)]
    last = blocks[-1]
    state = bytes(16)                   # C0

    for b in blocks[:-1]:
        state = shifr(X(b, state))

    if len(last) == 16:
        k = K1_s
    else:
        last = pad(last)
        k = K2_s
    return shifr(X(X(last, state), k))[:8]

print(imitostavka(P).hex() == '336f4d296059fbe3')
print(len(imitostavka(b'abc')) == 8)
