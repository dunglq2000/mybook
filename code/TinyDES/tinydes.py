sbox = [
    0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8, 0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7,
    0x0, 0xF, 0x7, 0x4, 0xE, 0x2, 0xD, 0x1, 0xA, 0x6, 0xC, 0xB, 0x9, 0x5, 0x3, 0x8,
    0x4, 0x1, 0xE, 0x8, 0xD, 0x6, 0x2, 0xB, 0xF, 0xC, 0x9, 0x7, 0x3, 0xA, 0x5, 0x0,
    0xF, 0xC, 0x8, 0x2, 0x4, 0x9, 0x1, 0x7, 0x5, 0xB, 0x3, 0xE, 0xA, 0x0, 0x6, 0xD
]


def Xor(a: list[int], b: list[int]) -> list[int]:
    return [x^y for x, y in zip(a, b)]


def Expand(R: list[int]) -> list[int]:
    return [R[2], R[3], R[1], R[2], R[1], R[0]]


def SBox(R: list[int]) -> list[int]:
    row = int("".join(map(str, [R[0], R[5]])), 2)
    col = int("".join(map(str, R[1:5])), 2)
    #eturn list(map(int, bin(sbox[row*16 + col])[2:].zfill(4)))
    return list(map(int, format(sbox[row*16 + col], "04b")))


def PBox(R: list[int]) -> list[int]:
    return [R[2], R[0], R[3], R[1]]


def PBox_inv(R: list[int]) -> list[int]:
    return [R[1], R[3], R[0], R[2]]


def Compress(K: list[int], round: int) -> list[int]:
    left, right = K[:4], K[4:]
    if round == 0 or round == 2:
        left = left[1:] + left[:1]
        right = right[1:] + right[:1]
    elif round == 1:
        left = left[2:] + left[:2]
        right = right[2:] + right[:2]

    Ki = left + right
    return left, right, [Ki[5], Ki[1], Ki[3], Ki[2], Ki[7], Ki[0]]


def encrypt_block(plaintext: list[int], key: list[int]) -> list[int]:
    keys = [key]
    left, right = key[:4], key[4:]
    for i in range(3):
        left, right, key = Compress(left + right, i)
        keys.append(key)

    left, right = plaintext[:4], plaintext[4:]
    for i in range(3):
        left, right = right, Xor(left, PBox(SBox(Xor(Expand(right), keys[i+1]))))
    
    return left + right

#print(encrypt_block([0, 1, 0, 1, 1, 1, 0, 0], [1, 0, 0, 1, 1, 0, 1, 0]))