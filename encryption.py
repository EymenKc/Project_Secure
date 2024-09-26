from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import make_base64
import base64

# AES encryption function
def encrypt_aes(data, key):
    # Generate a random 16-byte IV (Initialization Vector) derived from the key
    iv = key[:16] # Change this to a more secure method

    # Create a Cipher object using AES algorithm with CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the data to make sure it's a multiple of the block size (16 bytes for AES)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return the IV + ciphertext for decryption use
    return iv + ciphertext

# AES decryption function
def decrypt_aes(encrypted_data, key):
    # Extract the IV (first 16 bytes)
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    # Create a Cipher object using AES algorithm with CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the plaintext to get the original data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext

# Derive AES key from a password
def derive_key_from_password(password, salt, iterations=100000, key_length=32):
    # Convert the password to bytes if it's not already
    password_bytes = password.encode('utf-8')

    # PBKDF2 with HMAC-SHA256 as the hash function
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,  # 32 bytes for AES-256
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )

    # Derive the key
    key = kdf.derive(password_bytes)

    return key


def encrypt_data(file_path, password, salt):
    # Extract the file name without the extension
    name = file_path.split('/')[-1].split('.')[0]
    format = file_path.split('/')[-1].split('.')[1]

    # Convert the file to Base64
    base64_data = make_base64.file_to_base64(file_path).encode('utf-8')


    # Derive the AES key from the password
    key = derive_key_from_password(password, salt)

    # Encrypt the data
    encrypted_data = encrypt_aes(base64_data, key)


    # Add the encrypted format to the file name
    name = name + '.' + format

    print("name: ", name)

    # Encrypt the file name and encode it to hexadecimal string
    encrypted_file_name = encrypt_aes(name.encode('utf-8'), key).hex()

    # Write the encrypted data to a custom file type and save it to Encrypted_files folder
    with open("Encrypted_files/" + encrypted_file_name + ".crypt", "wb") as file:
        file.write(encrypted_data)


def decrypt_data(file_path, password, salt):

    # Derive the AES key from the password
    key = derive_key_from_password(password, salt)

    # Decrypt the data
    with open(file_path, "rb") as file:
        encrypted_data = file.read()

    decrypted_data = decrypt_aes(encrypted_data, key)

    # Decode the Base64 string to bytes
    decrypted_data = base64.b64decode(decrypted_data)

    # Get the file name from the file path
    file_name = file_path.split('/')[-1].split('.')[0]

    # Decode the file name
    decoded_file_name = bytes.fromhex(file_name)
    

    # Decrypt the file name and turn it into a string
    name = decrypt_aes(decoded_file_name, key).decode('utf-8')

    # Cut the format from the name
    format = name.split('.')[-1]
    only_name = name.split('.')[0]

    print(format)
    print(only_name)

    # Convert the decrypted data to a file
    make_base64.base64_to_file(only_name, decrypted_data, format, "Decrypted_files")
