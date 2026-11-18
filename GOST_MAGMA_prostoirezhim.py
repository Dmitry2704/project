#ГОСТ МАГМА - РЕЖИМ ПРОСТОЙ ОБРАБОТКИ
m = input('Введите текст для шифрования: ')
key = '0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20'
SBOX = [
    [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
    [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
    [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
    [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
    [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
    [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
    [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
    [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12],
]


def sbox(n):
    n_hex = hex(n)[2:].zfill(8)
    m = [int(i, 16) for i in n_hex][::-1]
    result = ''
    for j in range(8):
        result = hex(SBOX[j][m[j]])[2:] + result
    return result


def prost_rezh(c):
    m_bytes = c
    while len(m_bytes) % 16 != 0:
        m_bytes += '0'
    k = []
    for i in range(0, len(key), len(key)//8):
        k.append(key[i:i+8])

    blocks = []
    for i in range(0, len(m_bytes), 16):
        blocks.append([int(m_bytes[i:i+8], 16), int(m_bytes[i+8:i+16], 16)])

    for l in range(0, 24):
        for b in range(len(blocks)):
            N1, N2 = blocks[b]
            temp = N1
            n = (int(k[l % len(k)], 16) + N1) % (2**32)
            s_box = int(sbox(n), 16)
            result = ((s_box << 11) | (s_box >> (32 - 11))) & 0xFFFFFFFF
            result = result ^ N2
            N1, N2 = result, temp
            blocks[b] = [N1, N2]

    k_rev = k[::-1]
    for l in range(8):
        for b in range(len(blocks)):
            N1, N2 = blocks[b]
            temp = N1
            n = (int(k_rev[l % len(k_rev)], 16) + N1) % (2**32)
            s_box = int(sbox(n), 16)
            result = ((s_box << 11) | (s_box >> (32 - 11))) & 0xFFFFFFFF
            result = result ^ N2
            if l == 7:
                N2 = result
            else:
                N1, N2 = result, temp
            blocks[b] = [N1, N2]
    return blocks


ct = prost_rezh(bytes.hex(m.encode()))
out = ''
for b in ct:
    out += hex(b[0])[2:].zfill(8) + hex(b[1])[2:].zfill(8)
print(out)
