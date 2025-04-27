import yaml

def load_config(filename):
    # Vulnerable: Using unsafe yaml.load
    with open(filename, 'r') as f:
        return yaml.load(f.read())

def process_yaml_data(yaml_str):
    # Vulnerable: Using unsafe yaml.load with string
    return yaml.load(yaml_str)

# Example usage
try:
    config = load_config('config.yml')
except FileNotFoundError:
    config = {} 