import hashlib

def hash_data(data):
    # Vulnerable: Using SHA1 for hashing
    sha1_hasher = hashlib.sha1()
    sha1_hasher.update(data.encode('utf-8'))
    return sha1_hasher.hexdigest()

# Example usage
data = "sensitive information"
hashed = hash_data(data) 