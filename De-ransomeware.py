import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

# Define the decryption algorithm using AES-256
def decrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        file_data = f.read()
    iv = file_data[:16]
    encrypted_data = file_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data

# Function to decrypt all files in the specified directory
def decrypt_system(directory, key):
    files_to_decrypt = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            files_to_decrypt.append(os.path.join(root, file))
    
    # Decrypt the files
    for file in files_to_decrypt:
        try:
            decrypted_data = decrypt_file(file, key)
            with open(file, 'wb') as f:
                f.write(decrypted_data)
            print(f"Decrypted {file}")
        except Exception as e:
            print(f"Failed to decrypt {file}: {e}")

# Example usage
# Replace 'base64_encoded_key_here' with the actual base64 encoded key received during encryption
key = base64.b64decode("base64_encoded_key_here")

# Specify the directory to decrypt
directory_to_decrypt = '/path/to/encrypted/files'

# Start decryption
decrypt_system(directory_to_decrypt, key)