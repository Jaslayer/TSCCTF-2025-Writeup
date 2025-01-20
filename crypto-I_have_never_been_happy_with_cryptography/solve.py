from sympy import symbols, Eq, simplify
from Crypto.Util.number import getPrime, long_to_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
def positive_mod(n, p):
    return (n % p + p) % p

p = 42899
ciphertext = b'z\xa5\xa5\x1d\xe5\xd2I\xb1\x15\xec\x95\x8b^\xb6:r=\xe3h\x06-\xe9\x01\xda\xc03\xa4\xf6\xa8_\x8c\x12!MZP\x17O\xee\xa3\x0f\x05\x0b\xea7cnP'

'''
r = symbols('r[0:5]')
flag = [84, 83, 67, 123]

# 初始化r的方程式
r_eqs = [r[0], r[1], r[2], r[3], r[4]]

# 迴圈計算每次的r[0:5]的方程式
for i in range(4):
    r_eqs = [
        simplify(flag[i] + 1 * r_eqs[0]),
        simplify(flag[i] + 1 * r_eqs[0] + 2 * r_eqs[1]),
        simplify(flag[i] + 1 * r_eqs[0] + 2 * r_eqs[1] + 3 * r_eqs[2]),
        simplify(flag[i] + 1 * r_eqs[0] + 2 * r_eqs[1] + 3 * r_eqs[2] + 4 * r_eqs[3]),
        simplify(flag[i] + 1 * r_eqs[0] + 2 * r_eqs[1] + 3 * r_eqs[2] + 4 * r_eqs[3] + 5 * r_eqs[4])
    ]
    print(f"Iteration {i+1}: r = {r_eqs}")
'''

hash = [1934,22627,36616,21343]
memo = [[0 for _ in range(5)] for _ in range(4)]
for i in range(4):
    memo[i][4] = hash[i]
rows = len(memo)
cols = len(memo[0])

# 從右上到左下遍歷
for k in range(rows + cols - 1, -1, -1):
    for i in range(rows):
        j = k - i
        if 0 < j < cols-1:
            memo[i][j] = positive_mod(memo[i][j+1] - (j+2)*memo[i-1][j+1], p)
        if j==0:
            break
    if j==0:
        break

print(memo[-1])
for i in range(p):
    memo[-1][0] = i
    key = 0
    for rr in memo[-1]:
        key += rr
        key *= 2**16

    key = pad(long_to_bytes(key), 16)
    aes = AES.new(key, AES.MODE_ECB)
    print(f"key = {key}")
    try:
        plaintext = aes.decrypt(ciphertext)
        if(plaintext.startswith(b"TSC")):
            print(f"flag = {plaintext}")
            break
    except:
        continue