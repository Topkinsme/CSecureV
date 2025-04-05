'''from Crypto.PublicKey import RSA
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
'''
'''
from phe import paillier
public_key, private_key = paillier.generate_paillier_keypair()
msg="Hello there"
em=public_key.encrypt(msg.encode())
print(em)
dm=private_key.decrypt(em).decode()
print(dm)

print(private_key)
print(public_key)
'''
'''
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Generate Fernet key
fernet_key = Fernet.generate_key()
print("Original Fernet key:", fernet_key)
f = Fernet(fernet_key)
msg = "Simple and clean message"
token = f.encrypt(msg.encode())
print("Encrypted message:", token)
# Generate RSA keys
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()



# Encrypt Fernet key using RSA (simple padding)
encrypted_key = public_key.encrypt(
    fernet_key,
    padding.PKCS1v15()
)
print("Encrypted Fernet key:", encrypted_key)

# Decrypt Fernet key
decrypted_key = private_key.decrypt(
    encrypted_key,
    padding.PKCS1v15()
)
print("Decrypted Fernet key:", decrypted_key)

# Use it with Fernet
f = Fernet(decrypted_key)
decrypted_msg = f.decrypt(token).decode()
print("Decrypted message:", decrypted_msg)

print(public_key.exportKey(),private_key.exportKey())
'''
import rsa
from cryptography.fernet import Fernet

# Step 1: Generate RSA keys (from the simple rsa package)
(public_key, private_key) = rsa.newkeys(2048)

# Step 2: Generate a Fernet key
fernet_key = Fernet.generate_key()
print("Fernet key:", fernet_key)

# Step 3: Encrypt a message with Fernet
fernet = Fernet(fernet_key)
message = "This message is locked with Fernet."
encrypted_message = fernet.encrypt(message.encode())
print("Encrypted message:", encrypted_message)

# Step 4: Encrypt the Fernet key with RSA public key
encrypted_fernet_key = rsa.encrypt(fernet_key, public_key)
print("Encrypted Fernet key:", encrypted_fernet_key)

# Step 5: Decrypt the Fernet key with RSA private key
decrypted_fernet_key = rsa.decrypt(encrypted_fernet_key, private_key)
print("Decrypted Fernet key:", decrypted_fernet_key)

# Step 6: Decrypt the original message using the decrypted Fernet key
fernet2 = Fernet(decrypted_fernet_key)
decrypted_message = fernet2.decrypt(encrypted_message).decode()
print("Decrypted message:", decrypted_message)

public_pem = public_key.save_pkcs1().decode()
private_pem = private_key.save_pkcs1().decode()

# Print them
print("=== PUBLIC KEY ===")
print(public_pem)

print("=== PRIVATE KEY ===")
print(private_pem)

public_key = rsa.PublicKey.load_pkcs1(public_pem.encode())
private_key = rsa.PrivateKey.load_pkcs1(private_pem.encode())
print(public_key,private_key)