import random

def generate_token(length=32):
    # Vulnerable: Using insecure random for cryptographic purposes
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return ''.join(random.choice(charset) for _ in range(length))

# Example usage
token = generate_token()
print(f"Generated token: {token}") 