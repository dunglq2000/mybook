import aes
from itertools import product


def encrypt_two_round(pt: list[int], key: list[int]) -> list[int]:
    subkeys = aes.core.key_expansion(key, 128)

    t0 = aes.core.addroundkey(pt, subkeys[:16])

    t1 = aes.core.subbytes(t0)
    t1 = aes.core.shiftrows(t1)
    t1 = aes.core.mixcolumns(t1)
    t1 = aes.core.addroundkey(t1, subkeys[16:32])

    t2 = aes.core.subbytes(t1)
    t2 = aes.core.shiftrows(t2)
    t2 = aes.core.addroundkey(t2, subkeys[32:48])

    return t2


def xtime(a: int) -> int:
    #a = int(a,16)
    if (a & 0x80):
        return ((a << 1) ^ 0x1B) & 0xFF
        #return "{:02x}".format((((a << 1) ^ 0x1B) & 0xFF))
    else:
        return ((a << 1))
        #return "{:02x}".format((a << 1))

pt1 = list(range(16))
pt2 = [1] + list(range(1, 16))
pt3 = [2] + list(range(1, 16))
key = list(range(48, 64))

sbox = list(map(int, aes.core.sbox()))
inv_sbox = [sbox.index(i) for i in range(256)]

assert all(sbox[inv_sbox[i]] == i for i in range(256))

ct1 = encrypt_two_round(pt1, key)
ct2 = encrypt_two_round(pt2, key)
ct3 = encrypt_two_round(pt3, key)

subkeys = aes.core.key_expansion(key, 128)

f1, f2, f3 = ct1[0], ct2[0], ct3[0]
s1, s2, s3 = 0, 1, 2

print(s1, s2, s3)
print(pt1[0], pt2[0], pt3[0])

for k0, k0_ in product(range(256), repeat=2):
    s1 = inv_sbox[f1 ^ k0_]
    s2 = inv_sbox[f2 ^ k0_]
    s3 = inv_sbox[f3 ^ k0_]
    t1 = xtime(sbox[pt1[0] ^ k0])
    t2 = xtime(sbox[pt2[0] ^ k0])
    t3 = xtime(sbox[pt3[0] ^ k0])
    #t1 = xtime(sbox[0 ^ k0])
    #t2 = xtime(sbox[1 ^ k0])
    #t3 = xtime(sbox[2 ^ k0])
    if s1 ^ s2 == t1 ^ t2 and s1 ^ s3 == t1 ^ t3:
        print(k0, k0_)