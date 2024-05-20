from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import random

# Encrypt function
def encrypt_AES_CBC(plaintext, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv + ciphertext

# Decrypt function
def decrypt_AES_CBC(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    ciphertext = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

# Demo
print('Here\'s a demo of AES_CBC encrypting algorithm.\n')
message = b'Hello world, this message gonna be encrypted by AES CBC.'
key = get_random_bytes(16)  # 16 bytes for AES-128
# Encrypt a sample string
encrypted = encrypt_AES_CBC(message, key)
decrypted = decrypt_AES_CBC(encrypted, key)
print(f'Key used: 0x{key.hex()}')
print(f'Message: {message}\n')
print(f'Encrypted message: 0x{encrypted.hex()}\n' )

print(f'Decrypted message: 0x{decrypted.hex()}')
print('Now it\'s your turn. Enter the message to encrypt using AES_CBC. ')
# Encrypt your input
ur_msg = str(input('Your message: ')).encode()
encrypt_ur_msg = encrypt_AES_CBC(ur_msg, key)
print(f'\nYour message has been encrypted: 0x{encrypt_ur_msg.hex()}')
decrypt_ur_msg = decrypt_AES_CBC(encrypt_ur_msg, key)
print(f'\nDecrypted your message: {decrypt_ur_msg}')