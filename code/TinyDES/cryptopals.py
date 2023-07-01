import tinydes
from itertools import product


def int_to_vec6(n: int) -> list[int]:
    return list(map(int, format(n, "06b")))


def int_to_vec8(n: int) -> list[int]:
    return list(map(int, format(n, "08b")))


def vec_to_int(v: list[int]) -> int:
    return int("".join(map(str, v)), 2)


def recover_key(k: list[int]) -> list[int]:
    return [k[5], k[1], k[3], k[2], 0, k[0], 0, k[4]]


key = [1, 0, 0, 1, 1, 0, 1, 0]

ptx = []
ctx = []

pt, ct = [0, 1, 0, 1, 1, 1, 0, 0], [1, 0, 0, 1, 1, 0, 1, 0]

candidates = []
K3 = []

for _ in range(24):
    pt = int_to_vec8(_)
    ct = tinydes.encrypt_block(pt, key)
    pt_ = tinydes.Xor(int_to_vec8(0x83), pt)
    ct_ = tinydes.encrypt_block(pt_, key)
    if tinydes.Xor(ct_, ct) == list(map(int, format(0x38, "08b"))):
        ptx.append(pt_)
        ctx.append(ct_)
        candidates.append((pt, pt_))
        break

for pt1, pt2 in candidates:
    o1, o2 = tinydes.PBox_inv(pt1[4:]), tinydes.PBox_inv(pt2[4:])
    q1, q2 = tinydes.Expand(pt1[:4]), tinydes.Expand(pt2[:4])
    for i in range(len(tinydes.sbox)):
        if tinydes.sbox[i] == vec_to_int(o1):
            row, col = i // 16, i % 16
            idx = [row // 2] + list(map(int, format(col, "04b"))) + [row % 2]
            K3.append(tinydes.Xor(q1, idx))
        if tinydes.sbox[i] == vec_to_int(o2):
            row, col = i // 16, i % 16
            idx = [row // 2] + list(map(int, format(col, "04b"))) + [row % 2]
            K3.append(tinydes.Xor(q2, idx))

candidates = []

for _ in range(24):
    pt = int_to_vec8(_)
    ct = tinydes.encrypt_block(pt, key)
    pt_ = tinydes.Xor(int_to_vec8(0xb1), pt)
    ct_ = tinydes.encrypt_block(pt_, key)
    if tinydes.Xor(ct_, ct) == list(map(int, format(0x1b, "08b"))):
        ptx.append(pt_)
        ctx.append(ct_)
        candidates.append((pt, pt_))
        break

for pt1, pt2 in candidates:
    o1, o2 = tinydes.PBox_inv(pt1[4:]), tinydes.PBox_inv(pt2[4:])
    q1, q2 = tinydes.Expand(pt1[:4]), tinydes.Expand(pt2[:4])
    for i in range(len(tinydes.sbox)):
        if tinydes.sbox[i] == vec_to_int(o1):
            row, col = i // 16, i % 16
            idx = [row // 2] + list(map(int, format(col, "04b"))) + [row % 2]
            K3.append(tinydes.Xor(q1, idx))
        if tinydes.sbox[i] == vec_to_int(o2):
            row, col = i // 16, i % 16
            idx = [row // 2] + list(map(int, format(col, "04b"))) + [row % 2]
            K3.append(tinydes.Xor(q2, idx))

for k3 in set([vec_to_int(k) for k in K3]):
    k = recover_key(int_to_vec6(k3))
    for k4, k6 in product(range(2), repeat=2):
        k[4], k[6] = k4, k6
        if tinydes.encrypt_block(pt, k) == ct:
            print(f"Recover key: {k}")

'''
# Know about distribution of differential input-output
dist = []
for _ in range(2**6):
    X = int_to_vec6(_)
    row = [0] * 16
    for __ in range(2**6):
        X1 = int_to_vec6(__)
        X2 = tinydes.Xor(X, X1)
        Y1 = tinydes.SBox(X1)
        Y2 = tinydes.SBox(X2)
        Y = tinydes.Xor(Y1, Y2)
        #row.append(vec_to_int(Y))
        row[vec_to_int(Y)] += 1
    dist.append(row)

for i, row in enumerate(dist):
    print(f'Row = {row}')
    print(f'Row {i} has {row.count(0)} zero elements')
    print(f'Element that has maximal probability is {row.index(max(row))} with prob {max(row)}')
    print()
'''