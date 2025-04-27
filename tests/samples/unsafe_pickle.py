import pickle

def load_data(filename):
    # Vulnerable: Using unsafe pickle.loads
    with open(filename, 'rb') as f:
        return pickle.loads(f.read())

# Example usage
try:
    data = load_data('data.pkl')
except FileNotFoundError:
    data = {} 