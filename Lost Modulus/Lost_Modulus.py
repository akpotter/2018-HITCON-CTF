#!/usr/bin/env python
from Crypto.Util.number import *
from gmpy import *
from random import *
import sys,os

sys.stdin  = os.fdopen(sys.stdin.fileno(), 'r', 0)
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
rnd = SystemRandom()

# phi(n ** 2) = (p ** 2 - p) * (q ** 2 - q)
def calcA(g,n,data):
  num = bytes_to_long(data)
  res = pow(g, num, n * n) # (n + 1) ** flag % n ** 2 = flag * n + 1
  r = rnd.randint(0, n - 1)
  magic = pow(r, n, n * n) # r ** n % n ** 2
  res = (res * magic) % (n * n) # res = (flag * n + 1) * (r ** n) % n ** 2
  return long_to_bytes(res).encode('hex')

def calcB(phi,n,u,data):
  num = bytes_to_long(data) # Let data = calcA res
  res = pow(num, phi, n * n) # res = ((flag * n + 1) * (r ** n)) ** phi % n ** 2 = (phi * flag * n + 1) * (r ** n ** phi) % n ** 2 = phi * flag * n + 1
  res = (res - 1) / n # ((phi * flag * n + 1) - 1) / n = phi * flag
  res = (res * u) % n # phi * flag * u % n = flag
  return long_to_bytes(res).encode('hex')

if __name__ == '__main__':
  p = getPrime(512)
  q = getPrime(512)
  n = p * q
  phi = (p - 1) * (q - 1)
  g = n + 1
  u = invert(phi,n) # phi * u % n = 1 
  flag = open('flag').read()
  print 'Here is the flag!'
  print calcA(g,n,flag)
  for i in xrange(2048):
    m = raw_input('cmd: ')
    if m[0] == 'A':
      m = raw_input('input: ')
      try:
        m = m.decode('hex')
        print calcA(g,n,m)
      except:
        print 'no'
        exit(0)
    if m[0] == 'B':
      m = raw_input('input: ')
      try:
        m = m.decode('hex')
        print calcB(phi,n,u,m)[-2:]
      except:
        print 'no'
        exit(0)
