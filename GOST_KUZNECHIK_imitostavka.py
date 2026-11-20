p =  (252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240, 219, 147,
    46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66,
    139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11,237, 152, 127, 212, 211,31,235, 52, 44, 81,
    234, 200, 72, 171,242, 42, 104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19,
    71, 156, 183, 93, 135, 21,161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177, 50,
    117, 25, 61,255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223, 245, 36, 169, 62, 168, 67,
    201,215, 121,214, 246, 124, 34, 185, 3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78,
    51, 10, 74, 167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39,
    94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228,
    136, 217, 231, 137, 225, 27, 131,73, 76, 63, 248, 254, 141,83, 170, 144, 202, 216, 133, 97, 32, 113,
    103, 164, 45, 43, 9, 91,203, 155, 37, 208, 190, 229, 108, 82, 89, 166, 116, 210, 230, 244, 180, 192,
    209, 102, 175, 194, 57, 75, 99, 182)
m = 'Kuznechik is a block cipher #002'.encode()
blocks = []
for i in range(0, len(m), 16):
    blocks.append(m[i:i+16])
def s_box(block):
    block_s = []
    for i in block:
        block_s.append(p[i])
    return bytes(block_s)
def inv_sbox(block):
    block_s = []
    for i in block:
        block_s.append(p.index(i))
    return bytes(block_s)

def gmul(a, b):
    result = 0
    while b != 0:
        if b % 2 == 1:
            result ^= a
        a <<= 1
        if a & 256 == 256:
            a ^= int('1C3', 16)
        b >>= 1
    return result
const = [148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1]
def l(block):
    result = 0
    for a, b in zip(block, const):
        result ^= gmul(a, b)
    return result
def R(block_R):
    le = l(block_R)
    block_R = bytes([le]) + block_R[:-1]
    return block_R
def inv_R(block_R):
    block_R = block_R[1:] + bytes([l(block_R[1:] + block_R[:1])])
    return block_R
def L(block):
    for i in range(16):
        block = R(block)
    return block
def inv_L(block):
    for i in range(16):
        block = inv_R(block)
    return block
def X(a, K):
    blocks = []
    for x,y in zip(a, K):
        blocks.append(x^y)
    return bytes(blocks)
def C():
    block_C = []
    for i in range(1, 33):
        C_i = L(i.to_bytes(16, 'big'))
        block_C.append(C_i)
    return block_C

CONSTS = C()
K = '8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef'
K1 = bytes.fromhex('8899aabbccddeeff0011223344556677')
K2 = bytes.fromhex('fedcba98765432100123456789abcdef')
def F(k, a1, a0):
    x = X(k, a1)
    s = s_box(x)
    la = L(s)
    result = X(la, a0)
    return(result, a1)

blocks_K = []
blocks_K.append((K1, K2))
pair = K1, K2
for i in range(4):
    for j in range(8):
        pair = F(CONSTS[8*i+j], pair[0], pair[1])
    blocks_K.append(pair)
keys = []
for a, b in blocks_K:
    keys.append(a)
    keys.append(b)



def shifr(plaintext):
    state = plaintext
    for j in range(9):
        state = X(state, keys[j])  # берём текущее состояние
        state = s_box(state)  # перезаписываем результатом S
        state = L(state)  # перезаписываем результатом L
    state = X(state, keys[9])  # последний шаг, без S и L
    return state
def de_shifr(block):
    state = block
    for j in range(9, 0, -1):
        state = X(state, keys[j])
        state = inv_L(state)
        state = inv_sbox(state)
    state = X(state, keys[0])
    return state
f= ''
for i in blocks:
    f += shifr(i).hex()

bytes_shifr = bytes.fromhex(f)
blocks_deshifr = []
for i in range(0, len(bytes_shifr), 16):
    blocks_deshifr.append(bytes_shifr[i:i+16])
f = ''
for i in blocks_deshifr:
    f += de_shifr(i).hex()


def pad(block):
    return block + b'\x80' + bytes(15 - len(block) % 16)
def unpad(block):
    block = block.rstrip(b'\x00')
    if block[-1] != 0x80:
        raise ValueError("bad padding")
    return block[:-1]


def shift(block):
    x = int.from_bytes(block)
    star = x >> 127
    x = (x<<1) & ((1 << 128) - 1)
    if star == 1:
        x ^= int('87', 16)
    return int.to_bytes(x, 16)


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
    state = bytes(16)

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
