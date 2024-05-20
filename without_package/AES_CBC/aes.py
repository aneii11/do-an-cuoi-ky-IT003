from Crypto.Util.number import *
import random
import aes_h

key = long_to_bytes(random.getrandbits(128))
message = b'ImEncryptedByAES'

print(f'Used key: {hex(bytes_to_long(key))}')
print(f'Plain message: {message}')
cipher_text = aes_h.aes_encrypt(key, message)
print(f'Encrypted message: {hex(bytes_to_long(cipher_text))}')
plain_msg = aes_h.aes_decrypt(key,cipher_text)
print(f'Decrypted message: {plain_msg}')

