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
print("Here's a demo of RSA algorithm")
print('''
Key size selection:
1. 256 bits
2. 515 bits
3. 1024 bits
4. 2048 bits
      ''')
key_size = 0
option = int(input('Enter the option for key size: '))
match option:
    case 1:
        key_size = 256
    case 2:
        key_size = 512
    case 3:
        key_size = 1024
    case 4: 
        key_size = 2048
    case default:
        key_size = 0
assert key_size != 0, "Invalid option"

alice_public, alice_private = get_keys(key_size)
bob_public, bob_private = get_keys(key_size)
message = b"Hello, this message is going to be encrypted by RSA algorithm"
print('\nAlice\s keys: ')
print(f'Public key: {alice_public}')
print(f'Private key: {alice_private}')
print('\nBob\'s keys: ')
print(f'Public key: {bob_public}')
print(f'Private key: {bob_private}\n')
print(f'Plain message: {message}')
print('\nNow Alice encrypt the message and send to Bob')
encrypted_message = RSA_encrypt(bob_public, message)
print(f'\nEncrypted message to send to Bob: {encrypted_message}')
print('\nBob received encrypted message and decrypt it.')
decrypted_message = RSA_decrypt(bob_private, encrypted_message)
assert message == decrypted_message
print(f'Decrpyted message by Bob: {decrypted_message}')
print('\nNow it\'s your turn. Input your message and we will encrypt it with Alice\'s keys and sent to Alice.')
your_msg = str(input('Your message: ')).encode()
encrypted_ur_msg = RSA_encrypt(alice_public,your_msg)
print(f'\nEncrypted message to send to Alice: {encrypted_ur_msg}')
print(f'\nAlice received the message and decrypt it.')
decrypted_ur_msg = RSA_decrypt(alice_private,encrypted_ur_msg)
print(f'Decrypted message by Alice: {decrypted_ur_msg}')
    