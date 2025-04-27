from Crypto.Cipher import ARC4

def encrypt_with_rc4(key, data):
    # Vulnerable: Using deprecated RC4 algorithm
    cipher = ARC4.new(key)
    return cipher.encrypt(data)

# Example usage
key = b'insecure_rc4_key'
data = b'sensitive data to encrypt'
encrypted = encrypt_with_rc4(key, data) 