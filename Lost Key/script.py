import binascii
import sympy
from pwn import *

Hex = lambda x: '0' + hex(x)[2:] if len(hex(x)) & 1 else hex(x)[2:]

conn = remote("18.179.251.168", 21700)

conn.recvuntil('flag!\n')

ENC = int(conn.recvuntil('\n').strip('\n'), 16)

print("ENC = 0x{}".format(Hex(ENC)))

def oracle_enc(x):
    print("oracle enc")
    conn.recvuntil(': ') # cmd: 
    conn.sendline("A")
    conn.recvuntil(': ') # input: 
    conn.sendline(Hex(x))
    return int(conn.recvuntil('\n').strip('\n'), 16)

def oracle_dec(x):
    print "oracle dec"
    conn.recvuntil(': ') # cmd: 
    conn.sendline("B")
    conn.recvuntil(': ') # input: 
    conn.sendline(Hex(x))
    return int(conn.recvuntil('\n').strip('\n'), 16)

n = 0
a = 2
FF = 2 * 3 * 5 * 7 * 13 * 17 * 19 * 23 * 29 * 31 * 37 * 41 * 43 * 47 * 53 * 59 * 61 * 67 * 71 * 73 * 79 * 83 * 89 * 97
encrypted = oracle_enc(a)
while sympy.gcd(n, FF) > 1:
    # Let a ** e = m
    # encrypted = a ** e % n = r
    # encrypted_2 = (a ** e) ** 2 % n = r ** 2 % n
    # Let m = k_1 * n + r
    # encrypted ** 2 - encrypted_2 = (r ** 2) - (r ** 2 % n)
    # Let r ** 2 = k_2 * n + r' (k_2 >= 0)
    # encrypted ** 2 - encrypted_2 = (k_2 * n + r') - r' = k_2 * n
    # ==> gcd(n, encrypted ** 2 - encrypted_2) = 0 or n
    encrypted_2 = oracle_enc(a ** 2)
    n = sympy.gcd(n, encrypted_2 - encrypted ** 2)
    encrypted, a = encrypted_2, a ** 2

print("n = {}".format(str(n)))

plaintext = oracle_dec(ENC)
encrypted_8 = oracle_enc(2 ** 8)
inverse = sympy.invert(n % 2 ** 8, 2 ** 8)

# ENC = flag ** e % n 
# encrypted_8 = 2 ** 8 ** e % n
# t_cipher = encrypted_8 ** t % n = 2 ** (8 * t) ** e % n
# ENC * t_cipher % n = (flag * 2 ** (8 * t)) ** e % n
# ==> decrypt(ENC * t_cipher % n) 

k = 0
t = 1
t_cipher = 1
for _ in xrange(128):
    t = t * 2 ** 8 # record digest
    k = k * 2 ** 8 # record flag
    t_cipher = t_cipher * encrypted_8 % n
    res = oracle_dec(int(ENC * t_cipher % n))
    k += (t - k * plaintext - res) * inverse % 2 ** 8
    plaintext = int(k * n // t) + 1 # get ceil
    print(binascii.unhexlify(Hex(plaintext)))
    