from Crypto.Cipher import DES

def encrypt_with_des(key, data):
    # Vulnerable: Using deprecated DES algorithm
    cipher = DES.new(key, DES.MODE_CBC)
    return cipher.encrypt(data)

# Example usage
key = b'8bytekey'
data = b'sensitive data to encrypt'
encrypted = encrypt_with_des(key, data) 