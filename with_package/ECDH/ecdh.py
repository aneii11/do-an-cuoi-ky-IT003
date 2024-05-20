from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generate_ECDH_key_pair(option):
    curves = [ec.SECP192R1 ,ec.SECP256R1(), ec.SECP384R1() ]
    private_key = ec.generate_private_key(curve=curves[option-1])
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret

# Demo
print("This is a demo for ECDH key exchange algorithm.")
print("Key size selection")
print('''
1. 192 bits
2. 256 bits
3. 384 bits
      ''')
option = int(input('Enter option for key size: '))
# Get keys for Alice and Bob
alice_private_key, alice_public_key = generate_ECDH_key_pair(option)
bob_private_key, bob_public_key = generate_ECDH_key_pair(option)

# Alice computes shared secret
alice_shared_secret = derive_shared_secret(alice_private_key, bob_public_key)

# Bob computes shared secret
bob_shared_secret = derive_shared_secret(bob_private_key, alice_public_key)

# This part is just for demo. In pratice, both parties don't need to check if their secret is equal.
assert alice_shared_secret == bob_shared_secret

print("Shared Secret (in bytes):", alice_shared_secret)
print("Shared Secret (hexadecimal): 0x", alice_shared_secret.hex(), sep='')