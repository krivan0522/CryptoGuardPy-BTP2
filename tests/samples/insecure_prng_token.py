import random
import string

def generate_session_token(length=32):
    # Vulnerable: Using insecure random for token generation
    charset = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(charset) for _ in range(length))

def generate_temp_password():
    # Vulnerable: Using random.randint for security purposes
    digits = [str(random.randint(0, 9)) for _ in range(6)]
    return ''.join(digits)

# Example usage
token = generate_session_token()
temp_pass = generate_temp_password() 