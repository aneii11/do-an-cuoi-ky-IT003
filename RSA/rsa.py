from Crypto.Util.number import *
from Crypto.Util.number import getPrime
import time
# Generating public and private keys
def get_keys(bits_size: int):
    p = getPrime(bits_size)
    q = getPrime(bits_size)
    N = p*q
    phi_n = (p-1)*(q-1)
    e = 0x10001 # 0x10001 is the most common public keys, according to RSA standard
    d = pow(e,-1,phi_n)
    return (N,e), (N,d)

# Encrypting message using RSA algorithm
def RSA_encrypt(public_key, plaintext):
    N = public_key[0]
    e = public_key[1]
    plaintext_int = bytes_to_long(plaintext)
    assert plaintext_int < N, "message representative is out of range"
    return pow(plaintext_int, e, N)

# Decrypting message using RSA algorithm
def RSA_decrypt(private_key, ciphertext):
    N = private_key[0]
    d = private_key[1]
    assert ciphertext < N, "message representative is out of range"
    plaintext_int = pow(ciphertext,d,N)
    return long_to_bytes(plaintext_int)

# Demo
alice_public, alice_private = get_keys(2048)
bob_public, bob_private = get_keys(2048)
message = b"Hello, this message is going to be encrypted by RSA algorithm"
print('\nAlice\s keys: ')
print(f'Public key: {alice_public}')
print(f'Private key: {alice_private}')
print('\nBob\'s keys: ')
print(f'Public key: {bob_public}')
print(f'Private key: {bob_private}')
print(f'Plain message: {message}')
print('\nNow Alice encrypt message and send to Bob')
encrypted_message = RSA_encrypt(bob_public, message)
print(f'\nEncrypted message: {encrypted_message}')
print('\nBob received encrypted message and decrypt it')
decrypted_message = RSA_decrypt(bob_private, encrypted_message)
assert message == decrypted_message
print(f'Decrpyted message: {decrypted_message}')
    