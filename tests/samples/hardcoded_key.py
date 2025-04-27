from cryptography.fernet import Fernet

# Vulnerable: Hardcoded encryption key
ENCRYPTION_KEY = b'MyFixedEncryptionKey123456789012345678'

def encrypt_message(message):
    f = Fernet(ENCRYPTION_KEY)
    encrypted = f.encrypt(message.encode())
    return encrypted

# Example usage
secret_message = "sensitive data"
encrypted_data = encrypt_message(secret_message) 