from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Generate RSA keys
key = RSA.generate(2048)
private_key = key
public_key = key.publickey()
print(private_key,public_key)
# Encrypting
cipher = PKCS1_OAEP.new(public_key)
ciphertext = cipher.encrypt(b'This is a secret message.')

print("Ciphertext:", ciphertext)

# Decrypting
decipher = PKCS1_OAEP.new(private_key)
decrypted_message = decipher.decrypt(ciphertext)
print("Decrypted:", decrypted_message.decode())
