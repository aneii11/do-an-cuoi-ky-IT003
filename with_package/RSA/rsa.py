from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# generate key function
def generate_RSA_key_pair(key_size=2048):
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Encrypt function
def encrypt_RSA(plaintext, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext
# Decrypt function
def decrypt_RSA(ciphertext, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

# Demo
print("Here's a demo of RSA algorithm")
print('''
Key size selection:
1. 1024 bits
2. 2048 bits
3. 3072 bits
      ''')
key_size = 0
option = int(input('Enter the option for key size: '))
match option:
    case 1:
        key_size = 1024
    case 2: 
        key_size = 2048
    case 3:
        key_size = 3072
    case default:
        key_size = 0
assert key_size != 0, "Invalid option"

private_key, public_key = generate_RSA_key_pair(key_size=key_size)

# Encrypting a sample string
plaintext = b"Hello, this message is going to be encrypted by RSA algorithm."

encrypted = encrypt_RSA(plaintext, public_key)
decrypted = decrypt_RSA(encrypted, private_key)

print(f"Plaintext: {plaintext}\n")
print(f"Encrypted: 0x{encrypted.hex()}\n")
print("Decrypted:", decrypted.decode())
print('Now it\'s your turn. Send me a message and I will encrypt it with RSA')
your_msg = str(input('Your message: ')).encode()
encrypted_ur_msg = encrypt_RSA(your_msg, public_key)
print(f'\nEncrypted message to send to Alice: 0x{encrypted_ur_msg.hex()}')
print(f'\nAlice received the message and decrypt it.')
decrypted_ur_msg = decrypt_RSA(encrypted_ur_msg,private_key)
print(f'Decrypted message by Alice: {decrypted_ur_msg}')