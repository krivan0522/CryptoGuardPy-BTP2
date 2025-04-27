from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def encrypt_data(key, data):
    # Vulnerable: Using ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(data.encode(), AES.block_size)
    return cipher.encrypt(padded_data)

# Example usage
key = b'sixteen byte key'
data = "sensitive information"
encrypted = encrypt_data(key, data) 