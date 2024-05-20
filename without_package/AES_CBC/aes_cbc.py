from Crypto.Util.number import *
from Crypto.Util.strxor import strxor
import random
import aes_h

# Define padding, using PKCS7 padding scheme
def padding(text):
    len_text = len(text)
    pad_len = (len_text +16)//16 * 16
    return text + long_to_bytes(16-len_text%16)*(pad_len-len_text )

def aes_cbc_encrypt(key, plaintext):
    padded_plain = padding(plaintext)
    P = [padded_plain[i:i+16] for i in range(0,len(padded_plain),16)]
    IV = random.getrandbits(128)
    C = [long_to_bytes(IV)]
    for i in range(1,len(P)+1):
        C.append(aes_h.aes_encrypt(key, strxor(P[i-1], C[i-1])))
    ciphertext = b''.join([C[i] for i in range(0, len(P) + 1)])
    return ciphertext

def aes_cbc_decrypt(key, ciphertext):
    C = [ciphertext[i:i+16] for i in range(0,len(ciphertext),16)]
    IV = C[0]
    P = []
    for i in range(1, len(C)):
        P.append(strxor( aes_h.aes_decrypt(key,C[i]), C[i-1] ))
    plaintext = b''.join([P[i] for i in range(0,len(P))])
    padded_len = plaintext[-1]
    plaintext = plaintext[0:-padded_len]
    return plaintext

key = random.getrandbits(128)
key = long_to_bytes(key)
print('Here\'s a demo of AES_CBC encrypting algorithm.\n')
message = b'Hello world, this message gonna be encrypted by AES CBC.'
encrypted_msg = aes_cbc_encrypt(key,message)
print(f'Key used: {hex( bytes_to_long(key))}')
print(f'Message: {message}\n')
print(f'Encrypted message: 0x{encrypted_msg.hex()}\n' )
decrypted_msg = aes_cbc_decrypt(key,encrypted_msg)
print(f'Decrypted message: {decrypted_msg}')
print('Now it\'s your turn. Enter the message to encrypt using AES_CBC. ')
ur_msg = str(input('Your message: ')).encode()
encrypt_ur_msg = aes_cbc_encrypt(key, ur_msg)
print(f'\nYour message has been encrypted: 0x{encrypt_ur_msg.hex()}')
decrypt_ur_msg = aes_cbc_decrypt(key, encrypt_ur_msg)
print(f'\nDecrypted your message: {decrypt_ur_msg}')