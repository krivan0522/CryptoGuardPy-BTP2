import hashlib

def hash_password(password):
    # Vulnerable: Using MD5 for hashing
    md5_hasher = hashlib.md5()
    md5_hasher.update(password.encode('utf-8'))
    return md5_hasher.hexdigest()

# Example usage
password = "mysecretpassword"
hashed = hash_password(password) 