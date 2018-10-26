import sympy
import binascii
from pwn import *

conn = remote("13.112.92.9", 21701)

conn.recvuntil("flag!\n") # Here is the flag!

Hex = lambda x: '0' + hex(x)[2:] if len(hex(x)) & 1 else hex(x)[2:]

ENC = int(conn.recvuntil('\n').strip('\n'), 16)

print("ENC = 0x{}".format(Hex(ENC)))

def oracle_enc(x):
    print "oracle enc"
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

# 0. find n % 2**8
# for more stable solution allow n < 2**1023
t = 2 ** 1020
while True:
    res = oracle_dec(oracle_enc(t))
    if res != 0: break
    t *= 2

n8 =  2 ** 8 - res
print("{} -> {}".format(Hex(res), Hex(n8)))
assert n8 & 1

# 1. recover full n
# by finding k = floor(2 ** 2048 / n) byte-by-byte

# let  t = n * k + r,  r < n
# then n = floor(t / k) - floor(r / k)
# if   k > r (i.e. is large enough) then n = floor(t / k)

k = 0
t //= 2 # t < n
inverse = sympy.invert(n8, 2 ** 8)
while t < 2 ** 2048:
    t = t * 2 ** 8
    k = k * 2 ** 8
    res = oracle_dec(oracle_enc(t))
    k += (t - k * n8 - res) * inverse % 2 ** 8

n = t // k # floor
n2 = n ** 2
print("n = {}".format(str(n)))

# 2. decrypt flag
# by using homomorphic operations
def ctadd(c1, c2):
    return (c1 * c2) % n2

def ctmulconst(ciphertext, k):
    return pow(ciphertext, k, n2)

E1 = oracle_enc(1)  # we don't know g...

plaintext = 0
mod = 1
for _ in xrange(128):
    ciphertext = ENC
    ciphertext = ctadd(ciphertext, pow(int(E1), int((-plaintext) % n), int(n ** 2)))
    ciphertext = ctmulconst(ciphertext, sympy.invert(mod, n))
    low = oracle_dec(ciphertext)
    plaintext += mod * low
    mod *= 2 ** 8
    print(binascii.unhexlify(Hex(plaintext)))
