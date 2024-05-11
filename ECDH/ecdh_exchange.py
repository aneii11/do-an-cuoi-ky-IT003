from Crypto.Util.number import *
from random import getrandbits
# This function calculate addition in Elliptic Curve in finite group
# a, b means parameters in the elliptic curve, which is y^2 = x^3 + ax + b
# P, Q are operands
# p means modular of the finite group
def ecc_addition(P, Q, a, b, p):
    zero = (0, 0)
    if P == zero:
        return Q
    if Q == zero:
        return P
    if P[0] == Q[0] and P[1] == -1 * Q[1]:
        return zero
    if P == Q:
        l = (3 * P[0] ** 2 + a) * inverse(2 * P[1], p)
    else:
        l = (Q[1] - P[1]) * inverse(Q[0] - P[0], p)
    x3 = (l ** 2 - P[0] - Q[0]) % p
    y3 = (l * (P[0] - x3) - P[1]) % p
    return (x3, y3)

# This function calculate multiplication in Elliptic Curve in finity group
def ecc_multiply(P, n, a, b, p):
    Q = P
    R = (0, 0)
    while n > 0:
        if n % 2 == 1:
            R = ecc_addition(R, Q, a, b, p)
        Q = ecc_addition(Q, Q, a, b, p)
        n = n // 2
    return R

def ecdh_encrypt(a,b,p,G,n):
    # Abort if an invalid point is used
    assert G[1]**2 % p == (G[0]**3 + a*G[0] + b) % p, "The point is invalid in the current used curve"
    # Calculating public key Q = n*G
    return ecc_multiply(G,n,a,b,p) 

def ecdh_get_shared_secret(a,b,p,Q,n):
    # Abort if an invalid point is used
    assert G[1]**2 % p == (G[0]**3 + a*G[0] + b) % p, "The point is invalid in the current used curve"
    # Calculating shared secret K = nB*QA
    return ecc_multiply(Q,n,a,b,p)

# Demo
# Curves parameters. We are using secp256r1 curve 
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
print('Parameters: ')
print(f'{a=}')
print(f'{b=}')
print(f'{p=}')
print(f'{G=}')
# Choosing private keys for Alice(A) and Bob(B)
nA = getrandbits(256)
nB = getrandbits(256)
print('\nPrivate keys')
print(f'Alice\'s private key: {nA}')
print(f'Bob\'s private key: {nB}')
# Calculating public keys for Alice and Bob
QA = ecdh_encrypt(a,b,p,G,nA)
QB = ecdh_encrypt(a,b,p,G,nB)
print('\nPublic keys')
print(f'Alice\'s public key: {QA}')
print(f'Bob\'s public key: {QB}')
# Get shared secret
KA = ecdh_get_shared_secret(a,b,p,QB,nA)
KB = ecdh_get_shared_secret(a,b,p,QA,nB)
# This part is just for demo. In pratice, both parties don't need to check if their secret is equal
assert KA == KB, "Shared secrets are not equals"
print(f'\nShared secret is: {KA}')

