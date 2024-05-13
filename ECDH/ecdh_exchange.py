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
  
print("This is a demo for ECDH key exchange algorithm.")
print("Key size selection")
print('''
1. 192 bits
2. 256 bits
3. 384 bits
      ''')
option = int(input('Enter option for key size: '))
key_size = 0
match option:
    case 1:
        p = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
        a = 0xfffffffffffffffffffffffffffffffefffffffffffffffc
        b = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
        G = (0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012, 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811)
        key_size = 192
    case 2:
        p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
        a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
        b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
        G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
        key_size = 256
    case 3:
        p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff
        a = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc
        b = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef
        G = (0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7, 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f)
        key_size = 384        
    case default:
        key_size = 0
assert key_size != 0 ,"Invalid option"

# Choosing private keys for Alice(A) and Bob(B)
nA = getrandbits(key_size)
nB = getrandbits(key_size)
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

