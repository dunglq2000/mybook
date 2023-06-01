from typing import List

MODE_ECB = 0
MODE_CBC = 1

sbox = [
    [0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1],
    [0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF],
    [0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0],
    [0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB],
    [0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC],
    [0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0],
    [0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7],
    [0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2],
]

inv_sbox = [[sbox[i].index(j) for j in range(16)] for i in range(8)]

class GOSTMagma:
    def __init__(self, key: List[int], mode: int = MODE_ECB):
        self.key = key
        self.mode = mode

    @staticmethod
    def _encrypt_block(block: List[int], key: List[int]) -> List[int]:
        assert len(block) == 8
        assert len(key) == 32
        keys = [key[i:i+4] for i in range(0, len(key), 4)]
        left, right = [i for i in block[:4]], [i for i in block[4:]]
        for i in range(24):
            left, right = right, [x^y for x, y in zip(left, GOSTMagma._f(right, keys[i % 8]))]

        for i in range(24, 32):
            left, right = right, [x^y for x, y in zip(left, GOSTMagma._f(right, keys[7 - (i % 8)]))]

        return right + left
    
    @staticmethod
    def _decrypt_block(block: List[int], key: List[int]) -> List[int]:
        assert len(block) == 8
        assert len(key) == 32
        keys = [key[i:i+4] for i in range(0, len(key), 4)]
        left, right = [i for i in block[4:]], [i for i in block[:4]]
        for i in range(8):
            left, right = [x^y for x, y in zip(right, GOSTMagma._f(left, keys[i]))], left

        for i in range(8, 32):
            left, right = [x^y for x, y in zip(right, GOSTMagma._f(left, keys[7 - (i % 8)]))], left

        return left + right
    
    @staticmethod
    def _f(state: List[int], key: List[int]) -> List[int]:
        s = "".join(bin(i)[2:].zfill(8) for i in state)
        k = "".join(bin(i)[2:].zfill(8) for i in key)
        result = (int(s, 2) + int(k, 2)) % (2**32)
        tmp = bin(result)[2:].zfill(32)
        tmp = [int(tmp[i:i+4], 2) for i in range(0, len(tmp), 4)]
        tmp = [sbox[7-i][j] for i, j in enumerate(tmp)]
        tmp = int("".join(bin(i)[2:].zfill(4) for i in tmp), 2)
        tmp = bin(GOSTMagma.rot11(tmp))[2:].zfill(32)
        result = [int(tmp[i:i+8], 2) for i in range(0, len(tmp), 8)]
        return result
    
    @staticmethod
    def rot11(n: int) -> int:
        return ((n << 11) | (n >> 21)) & 0xffffffff
    
    @staticmethod
    def _encrypt_ecb(plaintext: List[int], key: List[int]) -> List[int]:
        assert len(plaintext) % 8 == 0, "Length of plaintext must be divided by 8"
        blocks = [plaintext[i:i+8] for i in range(0, len(plaintext), 8)]
        ciphertext = []
        for block in blocks:
            ciphertext += GOSTMagma._encrypt_block(block, key)
        return ciphertext
    
    def _decrypt_ecb(ciphertext: List[int], key: List[int]) -> List[int]:
        assert len(ciphertext) % 8 == 0
        blocks = [ciphertext[i:i+8] for i in range(0, len(ciphertext), 8)]
        plaintext = []
        for block in blocks:
            plaintext += GOSTMagma._decrypt_block(block, key)
        return plaintext
    
    def encrypt(self, plaintext: List[int]) -> List[int]:
        if self.mode == MODE_ECB:
            return GOSTMagma._encrypt_ecb(plaintext=plaintext, key=self.key)
        
    def decrypt(self, ciphertext: List[int]) -> List[int]:
        if self.mode == MODE_ECB:
            return GOSTMagma._decrypt_ecb(ciphertext=ciphertext, key=self.key)