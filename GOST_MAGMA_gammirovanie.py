МАГМА В РЕЖИМЕ ГАММИРОВАНИЯ
from pwn import xor  # ДОБАВЛЕНО: оставил, но по факту xor тут не нужен
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
sinxron = '123456789ABCDEF0'
C1 = int("00000010000000000000000000000000", 2)
C2 = int('00000010000100000000000000000000', 2)
def sbox(n):
    n_hex = hex(n)[2:].zfill(8)
    m = [int(i, 16) for i in n_hex][::-1]
    result = ''
    for j in range(8):
        result = hex(SBOX[j][m[j]])[2:] + result
    return result

f = ''

def prost_rezh(c):
    m_bytes = bytes.hex(c.encode())
    while len(m_bytes) % 8 != 0:
        m_bytes += '0'
    k = []
    for i in range(0, len(key), len(key)//8):
        k.append(key[i:i+8])

    # ДОБАВЛЕНО: переводим весь блок в числа заранее
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
            N1, N2 = result, temp
            blocks[b] = [N1, N2]
    return blocks
ct = prost_rezh(sinxron)
def gamma_block(ct):
    # ct — результат шифрования синхропосылки (список блоков)
    # Применяем константы ОДИН РАЗ к результату шифрования синхропосылки
    N2_g = (ct[0][1] + C1) % (2 ** 32 - 1)
    N1_g = (ct[0][0] + C2) % (2 ** 32)
    gamma_do = [[N1_g, N2_g]]

    # Выравниваем сообщение
    m_byte = bytes.hex(m.encode())
    while len(m_byte) % 16 != 0:
        m_byte += '0'

    # Разбиваем сообщение на блоки
    blocks = []
    for i in range(0, len(m_byte), 16):
        blocks.append([int(m_byte[i:i+8], 16), int(m_byte[i+8:i+16], 16)])

    while len(gamma_do) < len(blocks):
        last = gamma_do[-1]
        # Собираем последний гамма-блок в hex-строку для шифрования
        last_hex = hex(last[0])[2:].zfill(8) + hex(last[1])[2:].zfill(8)
        # Шифруем в простом режиме
        encrypted = prost_rezh(last_hex)
        # Получаем новый гамма-блок
        gamma_do.append([encrypted[0][0], encrypted[0][1]])

    # XOR-им сообщение с гаммой
    cipher_text = ''
    for i in range(len(blocks)):
        n1 = blocks[i][0] ^ gamma_do[i][0]
        n2 = blocks[i][1] ^ gamma_do[i][1]
        cipher_text += hex(n1)[2:].zfill(8) + hex(n2)[2:].zfill(8)

    return cipher_text
print(gamma_block(ct))

